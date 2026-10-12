"""Model health: has normal behaviour drifted away from what the model was trained on?

Compares each feature's distribution in recent normal activity with its training distribution
using the Population Stability Index (PSI = sum((recent - train) * ln(recent / train)) over the
training deciles), the standard drift measure in credit risk and ML monitoring:
  < 0.10 stable · 0.10-0.25 shifting · > 0.25 drifted.
It also compares the recent outlier rate with the ~3% the threshold was set for, and the model's age.
"""

import math
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import func
from sqlalchemy.orm import Session

from server.detection import ml_model
from server.detection.features import FEATURE_LABELS, FEATURE_NAMES, extract_event_features
from server.models import Event, IncidentEvent
from server.timeutil import as_utc

SHIFTING, DRIFTED = 0.10, 0.25
ROWS_PER_BIN = 6  # fewer bins for fewer recent rows: PSI from a handful of rows per bin is noise
SMOOTHING = 0.5  # Laplace pseudo-count per bin, so an empty bin is "rare", not "impossible"
TRAIN_WEIGHT = 100  # the training shares are treated as this many rows when smoothing
MIN_RECENT = 20
STALE_AFTER = timedelta(days=30)
OUTLIER_ALARM = 3.0  # recent outlier rate this many times the expected one


def psi(profile: dict, values: np.ndarray) -> float:
    """PSI of recent values against a training profile. The training deciles are merged into fewer
    bins when there are few recent rows, and values outside the whole training range get their own
    "below" and "above" bins: a value never seen in training is the strongest drift there is."""
    edges, shares = np.array(profile["edges"]), np.array(profile["shares"])
    k = int(min(len(shares), max(3, len(values) // ROWS_PER_BIN)))
    groups = np.array_split(np.arange(len(shares)), k)
    inner = [edges[g[0]] for g in groups] + [edges[-1]]
    inside = values[(values >= edges[0]) & (values <= edges[-1])]
    counts = np.concatenate(([np.sum(values < edges[0])], np.histogram(inside, bins=inner)[0], [np.sum(values > edges[-1])]))
    train = np.concatenate(([0.0], [shares[g].sum() for g in groups], [0.0]))
    bins = len(counts)
    recent_s = (counts + SMOOTHING) / (counts.sum() + SMOOTHING * bins)
    train_s = (train * TRAIN_WEIGHT + SMOOTHING) / (TRAIN_WEIGHT + SMOOTHING * bins)
    return float(sum((r - t) * math.log(r / t) for r, t in zip(recent_s, train_s)))


def band(value: float) -> str:
    return "drifted" if value > DRIFTED else "shifting" if value > SHIFTING else "stable"


def check(db: Session, days: float = 14) -> dict:
    bundle = ml_model._load()
    if bundle is None:
        return {"status": "not_trained", "reasons": ["No model is trained yet, so there is nothing to drift."], "features": []}
    if "profile" not in bundle:
        return {"status": "unknown", "reasons": ["This model was trained before drift monitoring existed: retrain it to enable the check."], "features": []}

    latest = db.query(func.max(Event.timestamp)).scalar()
    since = as_utc(latest) - timedelta(days=days)
    suspicious = {e for (e,) in db.query(IncidentEvent.event_id).all()}
    recent = [
        e
        for e in db.query(Event).filter(Event.event_type == "connect", Event.timestamp >= since).order_by(Event.timestamp).all()
        if e.id not in suspicious  # drift is about normal behaviour changing, not about attacks
    ]
    trained_at = bundle.get("trained_at")
    age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(trained_at)).days if trained_at else None
    out = {
        "algorithm": bundle.get("algorithm", "iforest"),
        "trained_at": trained_at,
        "model_age_days": age_days,
        "training_rows": bundle["training_rows"],
        "window_days": days,
        "recent_connections": len(recent),
        "expected_outlier_rate": ml_model.THRESHOLD_PERCENTILE / 100,
    }
    if len(recent) < MIN_RECENT:
        return {**out, "status": "insufficient_data", "reasons": [f"Only {len(recent)} normal connections in the last {days:g} days; need {MIN_RECENT} to judge drift."], "features": []}

    X = np.array([extract_event_features(db, e) for e in recent])
    outlier_rate = float(np.mean(bundle["model"].decision_function(X) < bundle["threshold"]))
    features = []
    for i, name in enumerate(FEATURE_NAMES):
        value = psi(bundle["profile"][i], X[:, i])
        features.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name.replace("_", " ")),
                "psi": round(value, 3),
                "band": band(value),
                "training_median": round(float(bundle["median"][i]), 3),
                "recent_median": round(float(np.median(X[:, i])), 3),
            }
        )
    features.sort(key=lambda f: -f["psi"])

    reasons = []
    drifted = [f for f in features if f["band"] == "drifted"]
    shifting = [f for f in features if f["band"] == "shifting"]
    if drifted:
        reasons.append("Drifted: " + ", ".join(f"{f['label']} (PSI {f['psi']:g})" for f in drifted) + ".")
    if shifting:
        reasons.append("Shifting: " + ", ".join(f"{f['label']} (PSI {f['psi']:g})" for f in shifting) + ".")
    high_outliers = outlier_rate > OUTLIER_ALARM * out["expected_outlier_rate"]
    if high_outliers:
        reasons.append(f"{outlier_rate:.0%} of recent normal connections score as outliers, against an expected {out['expected_outlier_rate']:.0%}: the baseline no longer fits.")
    stale = age_days is not None and age_days > STALE_AFTER.days
    if stale:
        reasons.append(f"The model is {age_days} days old.")

    status = "retrain_recommended" if drifted or high_outliers else "watch" if shifting or stale else "healthy"
    if status == "healthy":
        reasons.append("Recent normal behaviour matches the training baseline.")
    return {**out, "status": status, "recent_outlier_rate": round(outlier_rate, 3), "reasons": reasons, "features": features}
