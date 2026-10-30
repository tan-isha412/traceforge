"""The evasion experiment's headline results, so a change to the keystroke rule shows up here."""

import random

from server import evasion as ev


def rate(n_keys_per_s, cv, start=1.0, trials=30, seed=3):
    rng = random.Random(seed)
    hits = 0
    for _ in range(trials):
        caught, _ = ev.detected(ev.key_times(start, ev.gaps(rng, 299, 1 / n_keys_per_s, cv)))
        hits += caught
    return hits / trials


def test_ducky_speed_is_always_caught():
    assert rate(1000, 0.05) == 1.0


def test_just_under_the_rate_threshold_evades():
    assert rate(24, 0.35) <= 0.05


def test_chunked_delay_payload_is_caught():
    rng = random.Random(1)
    gaps = [0.25 if (i + 1) % 5 == 0 else 0.010 for i in range(299)]
    caught, _ = ev.detected(ev.key_times(1.0, gaps))
    assert caught


def test_waiting_out_the_window_evades_unless_hardened(monkeypatch):
    times = ev.key_times(31, [0.001] * 299)
    assert ev.detected(times) == (False, 0)
    monkeypatch.setattr(ev, "HARDENED", True)
    assert ev.detected(times)[0]
