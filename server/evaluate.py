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
from contextlib import contextmanager
from types import SimpleNamespace
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
from server.models import Anomaly, Event, IncidentEvent
from server.seed_synthetic_data import BASELINE, D, HID, INPUT, MASS, baseline_events, ev
from server.services.ingest import process_event
from server.timeutil import local_tz
from agent.keystrokes import summarize

MACHINES = ["LAB-PC-01", "LAB-PC-02", "LAB-PC-03", "LAB-PC-04", "ADMIN-LAPTOP"]
ATTACKS = ["type_switch", "serial_clone", "burst", "missing_serial", "descriptor_swap",
           "keystroke_injection", "ducky_with_delays", "night_exfiltration"]
BENIGN = "benign_unknown"
# Look-alikes that must NOT alert: a person typing on a known keyboard, a daytime copy to a known stick.
BENIGN_KINDS = [BENIGN, "human_typing", "daytime_copy"]
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
        # Clone a device the benign look-alike scenarios never use. Once its serial has been cloned the
        # genuine device keeps (rightly) tripping serial_reuse_across_models, which would leak one trial
        # into another and count as a false alarm on the benign typing/copy scenarios.
        name = rng.choice(["mouse", "webcam", "yubikey", "printer", "phone"])
        home = BASELINE[name][0][0]
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
    if kind in ("keystroke_injection", "ducky_with_delays", "human_typing"):
        machine, plugged = BASELINE["keyboard"][0][0], at(daytime, minute)
        if kind == "keystroke_injection":  # one fast, machine-regular burst
            gap = rng.uniform(0.004, 0.015)
            times = [rng.uniform(0.8, 2.5) + i * gap for i in range(rng.randint(80, 400))]
        elif kind == "ducky_with_delays":  # STRING bursts separated by DELAY pauses
            times, t = [], rng.uniform(0.8, 2.5)
            for _ in range(rng.randint(2, 5)):
                for _ in range(rng.randint(20, 80)):
                    times.append(t)
                    t += rng.uniform(0.006, 0.015)
                t += rng.uniform(1.5, 6.0)
        else:  # a person: 60-350 ms between keys, irregular
            times, t = [], rng.uniform(2, 8)
            for _ in range(rng.randint(40, 250)):
                times.append(t)
                t += rng.uniform(0.06, 0.35)
        return [
            ev(machine, "keyboard", "connect", plugged),
            ev(machine, "keyboard", "typing", plugged + timedelta(seconds=31), typing=summarize(times, 0.0, 30.0)),
        ]
    if kind in ("night_exfiltration", "daytime_copy"):
        name = rng.choice(["sandisk1", "sandisk2", "kingston"])
        machine = BASELINE[name][0][0]
        hour = night if kind == "night_exfiltration" else daytime
        size = rng.uniform(1, 6) * 1024**3 if kind == "night_exfiltration" else rng.uniform(20, 400) * 1024**2
        minutes = rng.randint(10, 60)
        return [
            ev(machine, name, "connect", at(hour, minute)),
            ev(machine, name, "disconnect", at(hour, minute) + timedelta(minutes=minutes),
               transfer={"bytes_written": int(size), "bytes_read": int(size * 0.02), "duration_s": minutes * 60.0}),
        ]
    if kind == BENIGN:
        fake = (f"{rng.randint(0x1000, 0xFFFF):04X}", f"{rng.randint(0x1000, 0xFFFF):04X}", f"NEW{rng.randint(10**7, 10**8 - 1)}", INPUT, HID)
        return [ev(home, fake, "connect", at(daytime, minute))]
    raise ValueError(kind)


def opened_incident(db, ids: list[int]) -> bool:
    """What actually alerts an investigator: any event of the trial joined an incident (NIST High,
    from one event or from the device's findings aggregated over 24 hours)."""
    return db.query(IncidentEvent).filter(IncidentEvent.event_id.in_(ids)).first() is not None


def source_scores(db, event_id: int) -> dict[str, float]:
    anomalies = db.query(Anomaly).filter(Anomaly.event_id == event_id).all()
    total = lambda src: min(100.0, sum(a.weight for a in anomalies if src is None or a.source == src))
    return {"hybrid": total(None), "rules": total("rule"), "ml": total("ml")}


def pct(hits: int, n: int) -> str:
    return f"{100 * hits / n:5.1f}% ({hits}/{n})" if n else "   n/a"


@contextmanager
def simulation(seed: int = 7, n_trials: int = 8):
    """Train on four weeks of synthetic normal use, replay two held-out weeks and the attack and
    benign trials, all in a throwaway in-memory database. Yields everything the reports need."""
    tz = local_tz()
    base_day = datetime(2026, 1, 5, tzinfo=tz)  # fixed Monday: results do not depend on today's date
    rng = random.Random(seed)

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    saved_path, saved_bundle = ml_model.MODEL_PATH, ml_model._bundle
    ml_model.MODEL_PATH = Path(tempfile.gettempdir()) / f"traceforge_eval_model_{seed}.joblib"
    ml_model._bundle = None

    everything = baseline_events(rng, base_day)
    cutoff = (base_day - timedelta(days=14)).astimezone(timezone.utc)
    train_events = [e for e in everything if e.timestamp < cutoff]
    held_out = [e for e in everything if e.timestamp >= cutoff]

    try:
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
            order = [(kind, i) for i in range(n_trials) for kind in ATTACKS + BENIGN_KINDS]
            rng.shuffle(order)
            for n, (kind, _) in enumerate(order, start=1):
                ids = [process_event(db, e).event.id for e in trial_events(kind, rng, base_day + timedelta(days=n))]
                trials.append((kind, ids))

            yield SimpleNamespace(db=db, train_events=train_events, X_train=X_train, normal=normal, trials=trials)
    finally:
        ml_model.MODEL_PATH.unlink(missing_ok=True)
        ml_model.MODEL_PATH, ml_model._bundle = saved_path, saved_bundle


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--trials", type=int, default=8, help="trials per scenario")
    parser.add_argument("--thresholds", type=float, nargs="+", default=[21.0, 80.0])
    parser.add_argument("--show-misses", action="store_true", help="list attack trials the hybrid detector missed")
    args = parser.parse_args()

    with simulation(args.seed, args.trials) as sim:
        report(sim, args)


def report(sim, args) -> None:
    db, train_events, X_train, normal, trials = sim.db, sim.train_events, sim.X_train, sim.normal, sim.trials
    print(f"training: {len(train_events)} events ({len(X_train)} connections)  |  held-out normal: {len(normal)} connections")
    print(f"attack trials: {args.trials} per scenario x {len(ATTACKS)} scenarios, plus {args.trials} x {len(BENIGN_KINDS)} benign look-alike scenarios\n")

    scores = {i: source_scores(db, i) for i in normal + [i for _, ids in trials for i in ids]}
    for threshold in args.thresholds:
        print(f"== Alert threshold: score >= {threshold:g} " + "=" * 40)
        print(f"{'Scenario (detection rate per trial)':<38}{'hybrid':>16}{'rules only':>16}{'ML only':>16}")
        for kind in ATTACKS + BENIGN_KINDS:
            group = [ids for k, ids in trials if k == kind]
            row = []
            for det in ("hybrid", "rules", "ml"):
                hits = sum(any(scores[i][det] >= threshold for i in ids) for ids in group)
                row.append(pct(hits, len(group)))
            label = kind + ("  [should NOT alert]" if kind in BENIGN_KINDS else "")
            print(f"{label:<38}" + "".join(f"{c:>16}" for c in row))
        row = [pct(sum(scores[i][det] >= threshold for i in normal), len(normal)) for det in ("hybrid", "rules", "ml")]
        print(f"{'held-out normal (false alarm rate)':<38}" + "".join(f"{c:>16}" for c in row) + "\n")

    # What actually reaches an investigator: an incident (NIST High from one event, or from the
    # device's findings aggregated over 24 hours, server/incidents/correlate.py).
    print("== Opened an incident (what alerts an investigator) " + "=" * 26)
    for kind in ATTACKS + BENIGN_KINDS:
        group = [ids for k, ids in trials if k == kind]
        label = kind + ("  [should NOT alert]" if kind in BENIGN_KINDS else "")
        print(f"{label:<38}{pct(sum(opened_incident(db, ids) for ids in group), len(group)):>16}")
    print(f"{'held-out normal (false alarm rate)':<38}{pct(sum(opened_incident(db, [i]) for i in normal), len(normal)):>16}\n")

    if args.show_misses:
        threshold = max(args.thresholds)
        print(f"== Attack trials missed by the hybrid detector at score >= {threshold:g} ==")
        for kind, ids in trials:
            if kind in BENIGN_KINDS or any(scores[i]["hybrid"] >= threshold for i in ids):
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


if __name__ == "__main__":
    main()
