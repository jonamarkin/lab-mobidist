#!/usr/bin/env python3
"""Analyze the JSON event log written by `go run ./cmd/experiment`.

Uses only the standard library. Writes CSV tables to results/ and, if
matplotlib is installed, plots as PNG files.

Statistics: for each configuration we compute one mean per seed (one
network), then report the mean and the variance/standard deviation of those
per-seed means, i.e. the spread between independent runs.
"""

import collections
import csv
import json
import math
import statistics
import sys

K = 10       # bucket size used in the experiments
RETRIES = 2  # RPC retransmissions after the first attempt


def load(path):
    """Return (lookup_done records, probe counts per lookup)."""
    done = []
    probes = collections.Counter()
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if "exp" not in rec:
                continue
            lookup = (rec["exp"], rec.get("n"), rec.get("loss"), rec["seed"], rec.get("node"), rec.get("lookup"))
            if rec["msg"] == "probe":
                probes[lookup] += 1
            elif rec["msg"] == "lookup_done":
                rec["_id"] = lookup
                done.append(rec)
    return done, probes


def cross_check(done, probes):
    """Every lookup's 'probes' field must equal the number of 'probe'
    events logged for it: two independent counts of the same thing."""
    bad = [r for r in done if r["probes"] != probes[r["_id"]]]
    print(f"cross-check: {len(done) - len(bad)}/{len(done)} lookups have probes == number of probe events")
    return not bad


def summarize(values):
    """Mean, variance, and standard deviation across seeds."""
    mean = statistics.fmean(values)
    var = statistics.variance(values) if len(values) > 1 else 0.0
    return mean, var, math.sqrt(var)


def per_seed(records, key, metric):
    """Group records by key(record) and seed; return {key: [per-seed mean]}."""
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in records:
        groups[key(r)][r["seed"]].append(metric(r))
    return {k: [statistics.fmean(v) for v in seeds.values()] for k, seeds in sorted(groups.items())}


def fit_line(xs, ys):
    """Least-squares fit y = a + b*x."""
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return my - b * mx, b


def experiment1(done):
    recs = [r for r in done if r["exp"] == "probes"]
    if not recs:
        return None
    probes = per_seed(recs, lambda r: r["n"], lambda r: r["probes"])
    hops = per_seed(recs, lambda r: r["n"], lambda r: r["hops"])
    exact = per_seed(recs, lambda r: r["n"], lambda r: 1.0 if r["found"] == min(K, r["n"] - 1) else 0.0)

    rows = []
    print("\nExperiment 1: lookup cost vs network size N (k=10, alpha=3, no loss)")
    print(f"{'N':>6} {'seeds':>5} {'probes':>14} {'var':>7} {'hops':>12} {'var':>7} {'log2N':>6} {'log2N/log2k':>11}")
    for n in probes:
        p, pv, ps = summarize(probes[n])
        h, hv, hs = summarize(hops[n])
        rows.append({"n": n, "seeds": len(probes[n]), "probes_mean": p, "probes_var": pv, "probes_sd": ps,
                     "hops_mean": h, "hops_var": hv, "hops_sd": hs, "full_result_rate": statistics.fmean(exact[n]),
                     "log2n": math.log2(n), "log2n_over_log2k": math.log2(n) / math.log2(K)})
        print(f"{n:>6} {len(probes[n]):>5} {p:>8.2f} ± {ps:<4.2f} {pv:>7.3f} {h:>6.2f} ± {hs:<4.2f} {hv:>7.4f}"
              f" {math.log2(n):>6.2f} {math.log2(n) / math.log2(K):>11.2f}")

    xs = [r["log2n"] for r in rows]
    a, b = fit_line(xs, [r["probes_mean"] for r in rows])
    ha, hb = fit_line(xs, [r["hops_mean"] for r in rows])
    print(f"fit: probes ≈ {a:.2f} + {b:.2f}·log2(N);  hops ≈ {ha:.2f} + {hb:.2f}·log2(N)")
    write_csv("results/exp1_probes.csv", rows)
    return rows


def experiment2(done):
    recs = [r for r in done if r["exp"] == "loss" and not r.get("local")]
    if not recs:
        return None
    success = per_seed(recs, lambda r: r["loss"], lambda r: 1.0 if r["value"] else 0.0)
    probes = per_seed(recs, lambda r: r["loss"], lambda r: r["probes"])
    failed = per_seed(recs, lambda r: r["loss"], lambda r: r["failed"] / max(1, r["probes"]))

    rows = []
    print("\nExperiment 2: value lookup success vs packet loss (N=500, k=10, alpha=3)")
    print(f"{'loss':>5} {'seeds':>5} {'success':>16} {'var':>9} {'probes':>13} {'failed probes':>13} {'1 RPC ok':>9}")
    for p in success:
        s, sv, ss = summarize(success[p])
        pr, _, prs = summarize(probes[p])
        fp, _, _ = summarize(failed[p])
        # Probability that one RPC succeeds: an attempt needs the request and
        # the response to get through, and there are 1+RETRIES attempts.
        rpc = 1 - (1 - (1 - p) ** 2) ** (1 + RETRIES)
        rows.append({"loss": p, "seeds": len(success[p]), "success_mean": s, "success_var": sv, "success_sd": ss,
                     "probes_mean": pr, "probes_sd": prs, "failed_probe_fraction": fp, "rpc_success_model": rpc})
        print(f"{p:>5.2f} {len(success[p]):>5} {100 * s:>8.1f}% ± {100 * ss:<4.1f} {sv:>9.5f} {pr:>7.1f} ± {prs:<4.1f}"
              f" {100 * fp:>12.1f}% {100 * rpc:>8.1f}%")
    write_csv("results/exp2_loss.csv", rows)
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}")


def plot(exp1, exp2):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed: skipping plots; the CSV files have all the data)")
        return
    if exp1:
        fig, ax = plt.subplots(figsize=(6, 4))
        ns = [r["n"] for r in exp1]
        ax.errorbar(ns, [r["probes_mean"] for r in exp1], yerr=[r["probes_sd"] for r in exp1], marker="o", capsize=3, label="probes per lookup")
        ax.errorbar(ns, [r["hops_mean"] for r in exp1], yerr=[r["hops_sd"] for r in exp1], marker="s", capsize=3, label="hops per lookup")
        ax.plot(ns, [r["log2n"] for r in exp1], "k--", label="log2 N")
        ax.plot(ns, [r["log2n_over_log2k"] for r in exp1], "k:", label="log2 N / log2 k")
        ax.set_xscale("log", base=2)
        ax.set_xlabel("network size N")
        ax.set_ylabel("count")
        ax.set_title("Lookup cost vs network size (mean ± sd over seeds)")
        ax.legend()
        fig.tight_layout()
        fig.savefig("results/exp1_probes.png", dpi=150)
        print("wrote results/exp1_probes.png")
    if exp2:
        fig, ax = plt.subplots(figsize=(6, 4))
        ps = [r["loss"] for r in exp2]
        ax.errorbar(ps, [100 * r["success_mean"] for r in exp2], yerr=[100 * r["success_sd"] for r in exp2], marker="o", capsize=3, label="lookup success")
        ax.plot(ps, [100 * r["rpc_success_model"] for r in exp2], "k--", label="single RPC success (model)")
        ax.set_xlabel("packet loss probability")
        ax.set_ylabel("success rate (%)")
        ax.set_ylim(0, 105)
        ax.set_title("Value lookup success vs packet loss (mean ± sd over seeds)")
        ax.legend()
        fig.tight_layout()
        fig.savefig("results/exp2_loss.png", dpi=150)
        print("wrote results/exp2_loss.png")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "results/experiments.jsonl"
    done, probes = load(path)
    ok = cross_check(done, probes)
    plot(experiment1(done), experiment2(done))
    if not ok:
        sys.exit("cross-check failed: the log is inconsistent")


if __name__ == "__main__":
    main()
