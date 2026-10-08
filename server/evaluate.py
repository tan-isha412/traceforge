"""Measure detection quality on synthetic data with known ground truth.

    python -m server.evaluate [--seed 7] [--trials 8]

Runs entirely in an in-memory database and a temporary model file, so it never touches
your real data or trained model. Training uses the first four weeks of normal usage;
the last two weeks are held out to measure false alarms. Attack trials are randomised
variants of the planted scenarios, each on its own day.

Caveat: the data is synthetic, so these numbers show the pipeline behaves as designed
on patterns we generated; they are not a claim about real-world accuracy.
"""

import argparse
import random
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server.database import Base
from server.detection import ml_model
from server.detection.features import build_training_matrix, extract_event_features
from server.models import Anomaly, Event
from server.seed_synthetic_data import BASELINE, D, HID, INPUT, MASS, baseline_events, ev
from server.services.ingest import process_event
from server.timeutil import local_tz

MACHINES = ["LAB-PC-01", "LAB-PC-02", "LAB-PC-03", "LAB-PC-04", "ADMIN-LAPTOP"]
ATTACKS = ["type_switch", "serial_clone", "burst", "missing_serial", "descriptor_swap"]
BENIGN = "benign_unknown"
BEHAVIOURAL = ("burst", "type_switch")  # scenarios where behaviour, not identity, is the signal


def trial_events(kind: str, rng: random.Random, day: datetime):
    at = lambda h, m=0, s=0: day.replace(hour=h, minute=m, second=s)
    night = rng.randint(0, 5)
    daytime = rng.randint(9, 16)
    minute = rng.randint(0, 59)
    name = rng.choice(list(D))
    home = BASELINE[name][0][0]

    if kind == "type_switch":
        name = rng.choice(["sandisk1", "sandisk2", "kingston"])
        machine = rng.choice([m for m in MACHINES if m not in BASELINE[name][0]])
        return [ev(machine, name, "connect", at(night, minute), dtype=INPUT, descriptor=HID)]
    if kind == "serial_clone":
        v = D[name]
        fake = (f"{rng.randint(0x1000, 0xFFFF):04X}", f"{rng.randint(0x1000, 0xFFFF):04X}", v[2], v[3], v[4])
        return [ev(home, fake, "connect", at(daytime, minute))]
    if kind == "burst":
        name = rng.choice(["mouse", "keyboard", "webcam", "printer"])
        machine, start, gap = BASELINE[name][0][0], at(night, minute), rng.randint(10, 40)
        return [ev(machine, name, "connect", start + timedelta(seconds=gap * i)) for i in range(rng.randint(6, 12))]
    if kind == "missing_serial":
        v = D[name]
        return [ev(home, (v[0], v[1], None, v[3], v[4]), "connect", at(daytime, minute))]
    if kind == "descriptor_swap":
        other = HID if D[name][4] is MASS else MASS
        return [ev(home, name, "connect", at(daytime, minute), descriptor=other)]
    if kind == BENIGN:
        fake = (f"{rng.randint(0x1000, 0xFFFF):04X}", f"{rng.randint(0x1000, 0xFFFF):04X}", f"NEW{rng.randint(10**7, 10**8 - 1)}", INPUT, HID)
        return [ev(home, fake, "connect", at(daytime, minute))]
    raise ValueError(kind)


def source_scores(db, event_id: int) -> dict[str, float]:
    anomalies = db.query(Anomaly).filter(Anomaly.event_id == event_id).all()
    total = lambda src: min(100.0, 5.0 + sum(a.weight for a in anomalies if src is None or a.source == src))
    return {"hybrid": total(None), "rules": total("rule"), "ml": total("ml")}


def pct(hits: int, n: int) -> str:
    return f"{100 * hits / n:5.1f}% ({hits}/{n})" if n else "   n/a"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--trials", type=int, default=8, help="trials per scenario")
    parser.add_argument("--thresholds", type=float, nargs="+", default=[25.0, 40.0])
    parser.add_argument("--show-misses", action="store_true", help="list attack trials the hybrid detector missed")
    args = parser.parse_args()

    tz = local_tz()
    base_day = datetime(2026, 1, 5, tzinfo=tz)  # fixed Monday: results do not depend on today's date
    rng = random.Random(args.seed)

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    ml_model.MODEL_PATH = Path(tempfile.gettempdir()) / "traceforge_eval_model.joblib"
    ml_model._bundle = None

    everything = baseline_events(rng, base_day)
    cutoff = (base_day - timedelta(days=14)).astimezone(timezone.utc)
    train_events = [e for e in everything if e.timestamp < cutoff]
    held_out = [e for e in everything if e.timestamp >= cutoff]

    with sessionmaker(bind=engine)() as db:
        for e in train_events:
            process_event(db, e)
        ml_model.train(db)
        X_train = np.array(build_training_matrix(db))

        normal: list[int] = []
        for e in held_out:
            out = process_event(db, e)
            if e.event_type == "connect":
                normal.append(out.event.id)

        trials: list[tuple[str, list[int]]] = []
        order = [(kind, i) for i in range(args.trials) for kind in ATTACKS + [BENIGN]]
        rng.shuffle(order)
        for n, (kind, _) in enumerate(order, start=1):
            ids = [process_event(db, e).event.id for e in trial_events(kind, rng, base_day + timedelta(days=n))]
            trials.append((kind, ids))

        print(f"training: {len(train_events)} events ({len(X_train)} connections)  |  held-out normal: {len(normal)} connections")
        print(f"attack trials: {args.trials} per scenario x {len(ATTACKS)} scenarios, plus {args.trials} benign unknown-device trials\n")

        scores = {i: source_scores(db, i) for i in normal + [i for _, ids in trials for i in ids]}
        for threshold in args.thresholds:
            print(f"== Alert threshold: score >= {threshold:g} " + "=" * 40)
            print(f"{'Scenario (detection rate per trial)':<38}{'hybrid':>16}{'rules only':>16}{'ML only':>16}")
            for kind in ATTACKS + [BENIGN]:
                group = [ids for k, ids in trials if k == kind]
                row = []
                for det in ("hybrid", "rules", "ml"):
                    hits = sum(any(scores[i][det] >= threshold for i in ids) for ids in group)
                    row.append(pct(hits, len(group)))
                label = kind + ("  [should NOT alert]" if kind == BENIGN else "")
                print(f"{label:<38}" + "".join(f"{c:>16}" for c in row))
            row = [pct(sum(scores[i][det] >= threshold for i in normal), len(normal)) for det in ("hybrid", "rules", "ml")]
            print(f"{'held-out normal (false alarm rate)':<38}" + "".join(f"{c:>16}" for c in row) + "\n")

        if args.show_misses:
            threshold = max(args.thresholds)
            print(f"== Attack trials missed by the hybrid detector at score >= {threshold:g} ==")
            for kind, ids in trials:
                if kind == BENIGN or any(scores[i]["hybrid"] >= threshold for i in ids):
                    continue
                e = db.get(Event, ids[0])
                first = db.query(func.min(Event.id)).filter(Event.device_id == e.device_id).scalar() == e.id
                print(
                    f"  {kind}: {e.device.vendor_id}:{e.device.product_id}/{e.device.serial_number} on {e.machine.hostname}, "
                    f"first sighting of this identity: {first}, findings: {[a.name for a in e.anomalies] or 'none'}"
                )
            print()

        # Model comparison on behavioural features only (no rules involved).
        iso = IsolationForest(n_estimators=200, random_state=42).fit(X_train)
        scaler = StandardScaler().fit(X_train)
        svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.03).fit(scaler.transform(X_train))
        models = {
            "Isolation Forest": lambda X: iso.decision_function(X),
            "One-Class SVM": lambda X: svm.decision_function(scaler.transform(X)),
        }
        feats = lambda ids: np.array([extract_event_features(db, db.get(Event, i)) for i in ids])
        normal_X = feats(normal)

        print("== ML model comparison (behavioural features only; threshold = 3rd percentile of training scores) ==")
        print(f"{'Model':<20}{'false alarms':>18}" + "".join(f"{k:>20}" for k in BEHAVIOURAL))
        for name, score in models.items():
            cut = np.percentile(score(X_train), 3)
            cells = [pct(int((score(normal_X) < cut).sum()), len(normal_X))]
            for kind in BEHAVIOURAL:
                group = [ids for k, ids in trials if k == kind]
                hits = sum(bool((score(feats(ids)) < cut).any()) for ids in group)
                cells.append(pct(hits, len(group)))
            print(f"{name:<20}{cells[0]:>18}" + "".join(f"{c:>20}" for c in cells[1:]))

    ml_model.MODEL_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
