"""Behavioural anomaly detector (Isolation Forest or One-Class SVM) with SHAP explanations."""

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sqlalchemy.orm import Session

from server.config import settings
from server.detection.features import (
    FEATURE_LABELS,
    FEATURE_NAMES,
    build_training_matrix,
    extract_event_features,
)
from server.detection.rules import Finding
from server.models import Event

MODEL_PATH = Path(__file__).resolve().parent.parent / "model_artifacts" / "iforest.joblib"
MIN_TRAINING_ROWS = 30
# Events scoring below this percentile of the training scores count as outliers,
# so roughly 3% of normal behaviour is flagged rather than whatever the default offset gives.
THRESHOLD_PERCENTILE = 3
SEVERITY_SPAN = 0.15  # Isolation Forest: how far below the threshold counts as maximum severity
OCSVM_NU = 0.05  # upper bound on the share of training points the One-Class SVM treats as outliers
BACKGROUND_ROWS = 50  # training rows kept for the One-Class SVM's SHAP explainer
MAX_WEIGHT = 45.0

_bundle: dict | None = None


def _load() -> dict | None:
    global _bundle
    if _bundle is None and MODEL_PATH.exists():
        loaded = joblib.load(MODEL_PATH)
        # A model saved with a different feature set cannot score current vectors; retrain instead.
        if loaded.get("features") == FEATURE_NAMES:
            _bundle = loaded
    # A model trained under another timezone learned a different meaning of "night",
    # and one trained with the other algorithm is not the detector that was asked for.
    if _bundle is not None and (
        _bundle.get("timezone") != settings.timezone or _bundle.get("algorithm", "iforest") != settings.ml_algorithm
    ):
        return None
    return _bundle


def status() -> dict:
    b = _load()
    return {
        "trained": b is not None,
        "algorithm": settings.ml_algorithm,
        "training_rows": b["training_rows"] if b else 0,
        "excluded_rows": b.get("excluded_rows", 0) if b else 0,
        "trained_at": b.get("trained_at") if b else None,
        "retrain_interval_hours": settings.retrain_interval_hours,
        "threshold": round(b["threshold"], 4) if b else None,
        "features": FEATURE_NAMES,
    }


PROFILE_BINS = 10


def _profile(column: np.ndarray) -> dict:
    """Decile edges of one feature in the training data and the share of rows in each bin."""
    edges = np.unique(np.quantile(column, np.linspace(0, 1, PROFILE_BINS + 1)))
    if len(edges) < 2:  # a feature that never varied: one bin around its value
        edges = np.array([column[0] - 0.5, column[0] + 0.5])
    counts, _ = np.histogram(np.clip(column, edges[0], edges[-1]), bins=edges)
    return {"edges": edges.tolist(), "shares": (counts / max(counts.sum(), 1)).tolist()}


def fit_bundle(X: np.ndarray, algorithm: str = "iforest") -> dict:
    if algorithm == "ocsvm":
        # SVM distances depend on feature scale, so the features are standardised first.
        model = make_pipeline(StandardScaler(), OneClassSVM(nu=OCSVM_NU, gamma="scale")).fit(X)
    else:
        model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
    scores = model.decision_function(X)
    threshold = float(np.percentile(scores, THRESHOLD_PERCENTILE))
    rng = np.random.default_rng(42)
    return {
        "model": model,
        "algorithm": algorithm,
        "timezone": settings.timezone,
        "threshold": threshold,
        # Decision values are on a different scale per algorithm; the gap from the threshold to the
        # most outlying training point is what counts as maximum severity for the One-Class SVM.
        "span": SEVERITY_SPAN if algorithm == "iforest" else max(threshold - float(scores.min()), 1e-6),
        "background": X[rng.choice(len(X), size=min(BACKGROUND_ROWS, len(X)), replace=False)],
        # Each feature's training distribution, for drift monitoring (server/detection/drift.py).
        "profile": [_profile(X[:, i]) for i in range(X.shape[1])],
        "training_rows": len(X),
        "features": FEATURE_NAMES,
        "median": np.median(X, axis=0),
        "std": X.std(axis=0) + 1e-9,
        # Isolation Forest cannot split on a feature that never varied in training, so it would
        # never notice a change there. Those features get a direct "never seen before" check.
        "constant": X.std(axis=0) < 1e-9,
        "min": X.min(axis=0),
        "max": X.max(axis=0),
    }


def train(db: Session) -> dict:
    global _bundle
    rows, excluded = build_training_matrix(db, with_excluded=True)
    if len(rows) < MIN_TRAINING_ROWS:
        raise ValueError(f"Need at least {MIN_TRAINING_ROWS} historical connect events to train, have {len(rows)}.")
    _bundle = fit_bundle(np.array(rows), settings.ml_algorithm)
    _bundle["excluded_rows"] = excluded
    _bundle["trained_at"] = datetime.now(timezone.utc).isoformat()
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(_bundle, MODEL_PATH)
    return status()


def _times(ratio: float) -> str:
    """'3.2x longer' / '180x shorter' for a ratio against a baseline."""
    r = ratio if ratio >= 1 else 1 / ratio
    return f"{r:.1f}x {'longer' if ratio >= 1 else 'shorter'}" if r < 10 else f"{r:,.0f}x {'longer' if ratio >= 1 else 'shorter'}"


def _describe(name: str, value: float, median: float) -> str:
    label = FEATURE_LABELS[name]
    if name == "gap_log":
        secs, base = np.expm1(value), np.expm1(median)
        return f"{label} was {secs:,.0f}s vs a typical {base:,.0f}s"
    if name == "gap_vs_baseline":
        return f"time since last connection was {_times(2**value)} than this device's historical baseline"
    if name == "hour_of_day":
        return f"{label} was {int(value):02d}:00 vs a typical {int(median):02d}:00"
    if name == "hour_deviation":
        return f"connected {value:.1f}h away from this device's usual time"
    if name == "enumeration_vs_baseline":
        return f"enumeration was {_times(2**value)} than this device's usual time"
    if name == "enumeration_order_changed":
        return "interfaces enumerated in a different order than last time" if value else "interfaces enumerated in the usual order"
    return f"{label} was {value:.0f} vs a typical {median:.0f}"


NOVEL_WEIGHT = 30.0
# How far outside the training range (as a fraction of that range) a value must be to count as unseen.
NOVEL_MARGIN = 1.0


def _novelty(bundle: dict, x: np.ndarray) -> list[Finding]:
    """Features far outside anything in the training data (or that never varied there but do now).
    Isolation Forest picks one random feature per split, so one extreme feature among many can
    still leave the overall score near normal; this check makes sure such a value is reported."""
    lo, hi = bundle["min"], bundle["max"]
    margin = (hi - lo) * NOVEL_MARGIN
    novel = [
        i
        for i, v in enumerate(x[0])
        if (bundle["constant"][i] and v != lo[i]) or v < lo[i] - margin[i] or v > hi[i] + margin[i]
    ]
    if not novel:
        return []
    texts = [_describe(FEATURE_NAMES[i], float(x[0][i]), float(bundle["median"][i])) for i in novel]
    return [
        Finding(
            "ml",
            "unseen_behaviour",
            NOVEL_WEIGHT,
            "Behaviour outside anything in the training baseline: " + "; ".join(texts) + ".",
            {"features": [FEATURE_NAMES[i] for i in novel], "values": [round(float(x[0][i]), 3) for i in novel]},
        )
    ]


def detect(db: Session, event: Event) -> list[Finding]:
    """Score one connect event; if it is an outlier, explain it with SHAP."""
    bundle = _load()
    if bundle is None:
        return []
    x = np.array([extract_event_features(db, event)])
    novelty = _novelty(bundle, x)
    score = float(bundle["model"].decision_function(x)[0])
    threshold = bundle["threshold"]
    if score >= threshold:
        return novelty

    import shap  # imported lazily: slow import, only needed on anomalies

    if bundle.get("algorithm", "iforest") == "ocsvm":
        background = shap.kmeans(bundle["background"], min(10, len(bundle["background"])))
        explainer = shap.KernelExplainer(bundle["model"].decision_function, background)
        contrib = np.asarray(explainer.shap_values(x, nsamples=200, silent=True)).reshape(-1)
    else:
        contrib = np.asarray(shap.TreeExplainer(bundle["model"]).shap_values(x)).reshape(-1)
    # For both detectors a lower decision value is more anomalous, so negative SHAP values
    # are the features pushing this connection toward "outlier".
    order = np.argsort(contrib)
    top = [i for i in order[:3] if contrib[i] < 0]
    drivers = [
        {
            "feature": FEATURE_NAMES[i],
            "shap_value": round(float(contrib[i]), 4),
            "value": round(float(x[0][i]), 3),
            "typical": round(float(bundle["median"][i]), 3),
            "text": _describe(FEATURE_NAMES[i], float(x[0][i]), float(bundle["median"][i])),
        }
        for i in top
    ]
    severity = min(1.0, (threshold - score) / bundle.get("span", SEVERITY_SPAN))
    weight = round(15 + (MAX_WEIGHT - 15) * severity, 1)
    why = "; ".join(d["text"] for d in drivers) or "overall behaviour deviates from the learned baseline"
    return [
        Finding(
            "ml",
            "behavioural_outlier",
            weight,
            f"Behaviour deviates from the learned baseline (SHAP): {why}.",
            {"algorithm": bundle.get("algorithm", "iforest"), "anomaly_score": round(score, 4), "drivers": drivers},
        )
    ] + novelty
