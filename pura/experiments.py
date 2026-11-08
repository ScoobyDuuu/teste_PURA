"""Protocolo experimental: N sementes x cenários x roteadores, com média, desvio-padrão e IC95%.

Uso:  python -m pura.experiments --seeds 30
Saídas em results/: runs.csv, summary.csv, results.json (usado pelo dashboard) e figuras .png
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import time
from typing import Dict, List

from .bandwidth import PSOAllocator, ProportionalAllocator
from .metrics import mean_std
from .routers import ROUTERS, ACORouter, make_router
from .scenario import build_scenario
from .simulator import Simulator

SURGES = (1.5, 2.0)
METRICS = ["lat_mean", "lat_p95", "goodput", "utility", "drop_frac", "risk", "recovery",
           "compute_ms", "over_budget", "J", "rej_zone", "rej_down"]
LOWER_BETTER = {"lat_mean", "lat_p95", "drop_frac", "risk", "recovery", "compute_ms", "J"}


def run_all(seeds: int) -> Dict:
    runs: List[Dict] = []
    for surge in SURGES:
        for seed in range(seeds):
            sc = build_scenario(seed, surge)
            for name in ROUTERS:
                res = Simulator(sc, make_router(name, seed * 7 + 1)).run()
                runs.append({"surge": surge, "seed": seed, "router": name, **res})
    return runs


def aggregate(runs: List[Dict]) -> Dict:
    summary: Dict = {}
    for surge in SURGES:
        summary[str(surge)] = {}
        for name in ROUTERS:
            rows = [r for r in runs if r["surge"] == surge and r["router"] == name]
            summary[str(surge)][name] = {}
            for m in METRICS:
                mu, sd = mean_std([r[m] for r in rows])
                summary[str(surge)][name][m] = {"mean": mu, "std": sd}
    return summary


def paired(runs: List[Dict], baselines=("dijkstra", "dijkstra_residual"),
           candidates=("aco", "memetic"), metrics=("lat_p95", "goodput", "J")) -> Dict:
    out: Dict = {}
    for surge in SURGES:
        out[str(surge)] = {}
        by = {(r["router"], r["seed"]): r for r in runs if r["surge"] == surge}
        seeds = sorted({r["seed"] for r in runs})
        for c in candidates:
            for b in baselines:
                key = f"{c}_vs_{b}"
                out[str(surge)][key] = {}
                for m in metrics:
                    diffs = [by[(c, s)][m] - by[(b, s)][m] for s in seeds]
                    mu, sd = mean_std(diffs)
                    ci = 1.96 * sd / math.sqrt(len(diffs)) if len(diffs) > 1 else float("nan")
                    sign = -1 if m in LOWER_BETTER else 1
                    wins = sum(1 for d in diffs if sign * d > 1e-9)
                    losses = sum(1 for d in diffs if sign * d < -1e-9)
                    out[str(surge)][key][m] = {"mean_diff": mu, "ci95": ci, "wins": wins,
                                               "ties": len(diffs) - wins - losses, "losses": losses}
    return out


def bandwidth_experiment(seeds: int) -> Dict:
    """PSO vs divisão proporcional, mesmas rotas (Dijkstra), cenário intenso."""
    res = {"proportional": [], "pso": []}
    for seed in range(seeds):
        sc = build_scenario(seed, 2.0)
        for name, alloc in (("proportional", ProportionalAllocator()), ("pso", PSOAllocator(seed))):
            s = Simulator(sc, make_router("dijkstra"), alloc).run()
            res[name].append(s["utility"])
    out = {k: dict(zip(("mean", "std"), mean_std(v))) for k, v in res.items()}
    diffs = [b - a for a, b in zip(res["proportional"], res["pso"])]
    mu, sd = mean_std(diffs)
    out["pso_minus_proportional"] = {"mean_diff": mu, "ci95": 1.96 * sd / math.sqrt(len(diffs))}
    return out


def sensitivity(seeds: int) -> List[Dict]:
    """Sensibilidade do ACO ao orçamento de iterações (cenário intenso)."""
    rows = []
    for iters in (2, 6, 12, 24):
        js, ms = [], []
        for seed in range(seeds):
            sc = build_scenario(seed, 2.0)
            r = ACORouter(seed=seed * 7 + 1, iters=iters)
            s = Simulator(sc, r).run()
            js.append(s["J"])
            ms.append(s["compute_ms"])
        rows.append({"iters": iters, "J_mean": statistics.fmean(js), "J_std": statistics.stdev(js),
                     "compute_ms": statistics.fmean(ms)})
    return rows


def timeseries(seed: int = 0) -> Dict:
    out = {}
    sc = build_scenario(seed, 2.0)
    for name in ROUTERS:
        sim = Simulator(sc, make_router(name, seed * 7 + 1))
        sim.run()
        out[name] = {"J": [round(r.J, 1) for r in sim.records],
                     "goodput": [round(r.goodput, 3) for r in sim.records],
                     "lat": [round(sum(r.lat) / len(r.lat), 1) if r.lat else None for r in sim.records]}
    out["events"] = [{"tick": e.tick, "kind": e.kind, "a": getattr(e, "a", ""), "b": getattr(e, "b", "")}
                     for e in sc.events]
    return out


def write_outputs(outdir: str, runs, summary, paired_, bw, sens, ts, seeds) -> None:
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "runs.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(runs[0].keys()))
        w.writeheader()
        w.writerows(runs)
    with open(os.path.join(outdir, "summary.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["surge", "router"] + [f"{m}_{k}" for m in METRICS for k in ("mean", "std")])
        for surge, d in summary.items():
            for name, ms in d.items():
                w.writerow([surge, name] + [round(ms[m][k], 4) for m in METRICS for k in ("mean", "std")])
    with open(os.path.join(outdir, "results.json"), "w") as fh:
        json.dump({"meta": {"seeds": seeds, "surges": SURGES, "routers": ROUTERS, "T": 60,
                            "generated": time.strftime("%Y-%m-%d %H:%M:%S")},
                   "summary": summary, "paired": paired_, "bandwidth": bw,
                   "sensitivity": sens, "timeseries": ts}, fh, indent=1)
    try:
        plot(outdir, summary, ts)
    except Exception as exc:  # matplotlib é opcional
        print("sem gráficos:", exc)


def plot(outdir: str, summary: Dict, ts: Dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"static": "#8a8a8a", "dijkstra": "#d1495b", "dijkstra_residual": "#edae49",
              "aco": "#00798c", "memetic": "#30638e"}
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    for ax, (m, title) in zip(axes, (("lat_p95", "Latência p95 (ms) — menor é melhor"),
                                     ("goodput", "Goodput (0–1) — maior é melhor"),
                                     ("J", "Função objetivo J — menor é melhor"))):
        width = 0.15
        for i, name in enumerate(ROUTERS):
            xs = [j + i * width for j in range(len(SURGES))]
            mu = [summary[str(s)][name][m]["mean"] for s in SURGES]
            sd = [summary[str(s)][name][m]["std"] for s in SURGES]
            ax.bar(xs, mu, width, yerr=sd, capsize=2, label=name, color=colors[name])
        ax.set_xticks([j + 2 * width for j in range(len(SURGES))])
        ax.set_xticklabels([f"pico ×{s}" for s in SURGES])
        ax.set_title(title, fontsize=10)
        if m == "J":
            ax.set_yscale("log")
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "comparacao.png"), dpi=130)
    plt.close(fig)

    fig, ax = plt.subplots(1, 2, figsize=(14, 4))
    for name in ROUTERS:
        ax[0].plot(ts[name]["J"], label=name, color=colors[name])
        ax[1].plot(ts[name]["goodput"], label=name, color=colors[name])
    for e in ts["events"]:
        for a in ax:
            a.axvline(e["tick"], color="#bbbbbb", lw=0.8, ls="--")
    ax[0].set_yscale("log")
    ax[0].set_title("J ao longo do tempo (semente 0, pico ×2.0); linhas = eventos", fontsize=10)
    ax[1].set_title("Goodput ao longo do tempo", fontsize=10)
    ax[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "serie_temporal.png"), dpi=130)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    t0 = time.time()
    runs = run_all(a.seeds)
    summary = aggregate(runs)
    bw = bandwidth_experiment(min(a.seeds, 15))
    sens = sensitivity(min(a.seeds, 15))
    write_outputs(a.out, runs, summary, paired(runs), bw, sens, timeseries(0), a.seeds)
    print(f"ok: {len(runs)} execuções em {time.time() - t0:.0f}s -> {a.out}/")


if __name__ == "__main__":
    main()
