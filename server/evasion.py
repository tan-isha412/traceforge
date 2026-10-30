"""Evasion experiment: how far must a keystroke-injection attacker go to slip past TraceForge?

    python -m server.evasion [--trials 200] [--payload 300] [--seed 7] [--plot docs/evasion.png] [--hardened]

TraceForge flags a newly connected keyboard that types faster or more regularly than a person
(Sigma rule usb_keystroke_injection.yml). An attacker who knows the rule can adapt. This experiment
plays three adaptive strategies against the detector and measures, for each setting, how often the
attack is still caught and what evasion costs the attacker in time:

  1. Slow down: type the payload at a lower rate, with or without random human-like jitter.
  2. Chunk:     type in fast bursts separated by pauses (Ducky STRING ... DELAY ...).
  3. Wait:      plug in, wait, then type at full speed, to start after the agent stops watching.

Everything detection-related is the real code, not a model of it: keystroke times go through the
agent's own summary (agent/keystrokes.py: summarize, the 30-second watch window, the 2000-key cap)
and the resulting report goes through the server's Sigma rule (server/detection/rules.py:
check_keystroke_injection). Only the attacker's key timing is simulated.

Timing model: gaps between keys are log-normal with the chosen mean and coefficient of variation
(CV = stdev / mean; 0 = a metronome, ~0.3-0.6 = the irregularity of human typing). A trial counts as
detected when the keystroke_injection finding fires on the typing report the agent would send.

--hardened measures two candidate countermeasures that are NOT deployed: a "metronome" test (15+ keys
with gap CV under 0.1 is a machine at any speed) and a 300-second watch window instead of 30. They are
kept out of the live detector until tested on real hardware, because a longer window also lengthens
the time in which a person holding down a key (auto-repeat) on a newly connected keyboard could be
mistaken for injection.

Caveat: simulated timings. Real hardware adds USB polling jitter (1-8 ms per report) that is not
modelled here; validating these numbers with a programmable board (Digispark, Arduino Pro Micro)
is future work.
"""

import argparse
import math
import random
from dataclasses import dataclass

from agent.keystrokes import MAX_KEYS, WATCH_SECONDS, summarize
from server.detection.rules import check_keystroke_injection

DUCKY_GAP_S = 0.001  # Rubber Ducky default: about 1000 keys/s
HUMAN_RATE = 6.0  # a fast typist sustains roughly 5-8 keys/s


@dataclass
class Result:
    strategy: str
    setting: str
    detected: float  # share of trials caught
    payload_s: float  # median time to type the whole payload, from plug-in
    keys_seen: float  # median keys inside the agent's watch window


def gaps(rng: random.Random, n: int, mean_s: float, cv: float) -> list[float]:
    """n inter-key gaps, log-normal with the given mean and coefficient of variation."""
    if cv <= 0:
        return [mean_s] * n
    sigma = math.sqrt(math.log(1 + cv * cv))
    mu = math.log(mean_s) - sigma * sigma / 2
    return [rng.lognormvariate(mu, sigma) for _ in range(n)]


def key_times(start_s: float, gap_list: list[float]) -> list[float]:
    t, out = start_s, [start_s]
    for g in gap_list:
        t += g
        out.append(t)
    return out


HARDENED_WINDOW_S = 300.0
METRONOME_CV = 0.1
HARDENED = False  # set by --hardened


def detected(times: list[float]) -> tuple[bool, int]:
    """What the real agent and the real Sigma rule make of these key-down times (seconds after plug-in)."""
    window = HARDENED_WINDOW_S if HARDENED else WATCH_SECONDS
    seen = [t for t in times if t < window][:MAX_KEYS]
    if not seen:  # the agent reports nothing when no key was pressed while it watched
        return False, 0
    report = summarize(seen, connected_at=0.0, watched_s=window)
    caught = bool(check_keystroke_injection(report))
    if HARDENED and report.get("keys", 0) >= 15 and report.get("gap_cv", 1.0) < METRONOME_CV:
        caught = True
    return caught, len(seen)


def run(strategy: str, setting: str, make_times, trials: int, rng: random.Random) -> Result:
    hits, durations, seen_counts = 0, [], []
    for _ in range(trials):
        times = make_times(rng)
        caught, seen = detected(times)
        hits += caught
        durations.append(times[-1])
        seen_counts.append(seen)
    med = lambda xs: sorted(xs)[len(xs) // 2]
    return Result(strategy, setting, hits / trials, med(durations), med(seen_counts))


def experiment(trials: int, payload: int, seed: int) -> list[Result]:
    rng = random.Random(seed)
    n = payload - 1
    start = 1.0  # first key a second after plug-in (a Digispark's bootloader adds ~5 s more)
    results = []

    for rate in (1000, 100, 50, 30, 26, 24, 20, 15, 10, 6):
        for cv in (0.0, 0.1, 0.35, 0.6):
            results.append(run("slow down", f"{rate} keys/s, CV {cv:g}",
                               lambda r, rate=rate, cv=cv: key_times(start, gaps(r, n, 1 / rate, cv)), trials, rng))

    for burst in (2, 3, 5, 10, 20):
        for pause in (0.25, 1.0):
            def chunked(r, burst=burst, pause=pause):
                g = []
                for i in range(n):
                    g.append(pause if (i + 1) % burst == 0 else gaps(r, 1, 0.010, 0.2)[0])
                return key_times(start, g)
            results.append(run("chunk", f"bursts of {burst} keys at 100 keys/s, {pause:g} s pauses", chunked, trials, rng))

    for delay in (5, 15, 25, 29, 29.9, 30, 31, 60, 299, 301):
        results.append(run("wait", f"wait {delay:g} s, then Ducky speed",
                           lambda r, delay=delay: key_times(delay, gaps(r, n, DUCKY_GAP_S, 0.05)), trials, rng))
    return results


def print_table(results: list[Result], payload: int) -> None:
    window = HARDENED_WINDOW_S if HARDENED else WATCH_SECONDS
    extra = " HARDENED variant: + metronome test (CV < 0.1)." if HARDENED else ""
    print(f"Payload: {payload} keystrokes. Watch window: {window:g} s after plug-in.{extra} "
          f"Detected = share of trials where keystroke_injection fired.\n")
    current = None
    for r in results:
        if r.strategy != current:
            current = r.strategy
            print(f"== {current} " + "=" * 60)
            print(f"{'setting':<46}{'detected':>10}{'payload time':>14}{'keys watched':>14}")
        print(f"{r.setting:<46}{r.detected:>9.0%}{r.payload_s:>13.1f}s{r.keys_seen:>14.0f}")
    print()


def cheapest_evasion(results: list[Result], baseline_s: float) -> None:
    """For each strategy, the fastest setting that evades at least 95% of the time."""
    print("== Cheapest evasion per strategy (detected in at most 5% of trials) ==")
    for strategy in dict.fromkeys(r.strategy for r in results):
        evading = [r for r in results if r.strategy == strategy and r.detected <= 0.05]
        if not evading:
            print(f"{strategy:<12} never evades in this grid")
            continue
        best = min(evading, key=lambda r: r.payload_s)
        print(f"{strategy:<12} {best.setting:<46} {best.payload_s:6.1f} s  ({best.payload_s / baseline_s:,.0f}x the undetected-attacker baseline)")
    print()


def plot(results: list[Result], path: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 4.5))
    slow = [r for r in results if r.strategy == "slow down"]
    for cv, style in (("0", "o-"), ("0.1", "s-"), ("0.35", "^-"), ("0.6", "d-")):
        pts = [(float(r.setting.split()[0]), r.detected) for r in slow if r.setting.endswith(f"CV {cv}")]
        ax.plot([p[0] for p in pts], [p[1] * 100 for p in pts], style, label=f"jitter CV {cv}")
    ax.axvline(25, color="grey", linestyle=":", linewidth=1)
    ax.text(25, 50, " 25 keys/s rate rule", color="grey", fontsize=8)
    ax.axvspan(5, 8, color="tab:green", alpha=0.08)
    ax.text(5.2, 8, "human typing", color="tab:green", fontsize=8)
    ax.set_xscale("log")
    ax.set_xlabel("attacker typing rate (keys/s, log scale)")
    ax.set_ylabel("detected (% of trials)")
    ax.set_title("Keystroke-injection detection vs attacker typing rate")
    ax.set_ylim(-5, 105)
    ax.legend(loc="center right", fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"plot saved to {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=200)
    parser.add_argument("--payload", type=int, default=300, help="keystrokes in the attack payload")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--plot", help="save a detection-vs-rate plot to this PNG")
    parser.add_argument("--hardened", action="store_true", help="measure the candidate countermeasures (not deployed)")
    args = parser.parse_args()
    global HARDENED
    HARDENED = args.hardened

    results = experiment(args.trials, args.payload, args.seed)
    print_table(results, args.payload)
    baseline = 1.0 + (args.payload - 1) * DUCKY_GAP_S
    cheapest_evasion(results, baseline)
    if args.plot:
        plot(results, args.plot)


if __name__ == "__main__":
    main()
