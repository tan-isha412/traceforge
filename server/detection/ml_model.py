"""Isolation Forest behavioural anomaly detector with SHAP explanations."""

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from server.detection.features import (
    FEATURE_LABELS,
    FEATURE_NAMES,
    build_training_matrix,
    extract_event_features,
)
from server.config import settings
from server.detection.rules import Finding
from server.models import Event

MODEL_PATH = Path(__file__).resolve().parent.parent / "model_artifacts" / "iforest.joblib"
MIN_TRAINING_ROWS = 30
# Events scoring below this percentile of the training scores count as outliers,
# so roughly 3% of normal behaviour is flagged rather than whatever the default offset gives.
THRESHOLD_PERCENTILE = 3
SEVERITY_SPAN = 0.15  # how far below the threshold counts as maximum severity
MAX_WEIGHT = 45.0

_bundle: dict | None = None


def _load() -> dict | None:
    global _bundle
    if _bundle is None and MODEL_PATH.exists():
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def status() -> dict:
    b = _load()
    return {
        "trained": b is not None,
        "training_rows": b["training_rows"] if b else 0,
        "threshold": round(b["threshold"], 4) if b else None,
        "features": FEATURE_NAMES,
    }


def fit_bundle(X: np.ndarray) -> dict:
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
    return {
        "model": model,
        "threshold": float(np.percentile(model.decision_function(X), THRESHOLD_PERCENTILE)),
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
    rows = build_training_matrix(db)
    if len(rows) < MIN_TRAINING_ROWS:
        raise ValueError(f"Need at least {MIN_TRAINING_ROWS} historical connect events to train, have {len(rows)}.")
    X = np.array(rows)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
    _bundle = {
        "model": model,
        "threshold": float(np.percentile(model.decision_function(X), THRESHOLD_PERCENTILE)),
        "training_rows": len(rows),
        "median": np.median(X, axis=0),
        "std": X.std(axis=0) + 1e-9,
    }
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

    explainer = shap.TreeExplainer(bundle["model"])
    contrib = np.asarray(explainer.shap_values(x)).reshape(-1)
    # In Isolation Forest, negative SHAP values push the point toward "anomalous".
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
    severity = min(1.0, (threshold - score) / SEVERITY_SPAN)
    weight = round(15 + (MAX_WEIGHT - 15) * severity, 1)
    why = "; ".join(d["text"] for d in drivers) or "overall behaviour deviates from the learned baseline"
    return [
        Finding(
            "ml",
            "behavioural_outlier",
            weight,
            f"Behaviour deviates from the learned baseline (SHAP): {why}.",
            {"anomaly_score": round(score, 4), "drivers": drivers},
        )
    ] + novelty
