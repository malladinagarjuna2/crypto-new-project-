#!/usr/bin/env python3
"""Contribution B: measure when the partitioning attack stops being practical.

Turns the theoretical "~log2(N) queries" into a real curve on this machine and
finds where a slow KDF makes the attack impractical. Writes a chart-ready CSV
and regenerates four figures from it (no numbers are hardcoded into the plots).

    # run the sweep and (re)draw figures
    python experiments/measure_practicality.py

    # redraw figures from an existing CSV only
    python experiments/measure_practicality.py --plot-only

Because pure binary search forges for N/2 keys at the first step (cost grows
~O(N^2)) and the slow KDF derives ~N keys per run (~90 ms each), defaults are
kept modest. Push them up with --sizes / --slow-max-n when you have time; the
trends are already visible at small N.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys
import tracemalloc
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from pogcm import kdf as kdfs
from pogcm.attack import AttackStats, recover_password
from pogcm.oracle import VulnerableServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
FIGS = os.path.join(ROOT, "figures")
CSV_PATH = os.path.join(DATA, "practicality.csv")
SPLIT_CSV_PATH = os.path.join(DATA, "split_sweep.csv")
PW_FILE = os.path.join(DATA, "sample_passwords.txt")

FIELDS = [
    "N",
    "kdf",
    "split_size",
    "queries",
    "log2N",
    "total_seconds",
    "kdf_seconds",
    "forge_seconds",
    "oracle_seconds",
    "keys_derived",
    "max_ct_bytes",
    "peak_mem_bytes",
    "recovered_ok",
]


def load_dictionary(n: int, seed: int) -> List[str]:
    """Sample n distinct candidate passwords from the public sample list."""
    with open(PW_FILE) as f:
        pool = [line.strip() for line in f if line.strip()]
    rng = random.Random(seed)
    if n <= len(pool):
        return rng.sample(pool, n)
    # Not enough real entries; pad deterministically with synthetic ones.
    extra = [f"syn« {i} »pw" for i in range(n - len(pool))]
    cands = pool + extra
    rng.shuffle(cands)
    return cands


def run_one(n: int, kdf_name: str, split_size, seed: int) -> dict:
    kdf = kdfs.KDFS[kdf_name]
    candidates = load_dictionary(n, seed)
    secret = random.Random(seed + 7).choice(candidates)
    server = VulnerableServer(secret, candidates, kdf)

    stats = AttackStats()
    tracemalloc.start()
    recovered = recover_password(
        server, candidates, kdf, split_size=split_size, stats=stats
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "N": n,
        "kdf": kdf_name,
        "split_size": split_size if split_size is not None else "half",
        "queries": stats.queries,
        "log2N": round(math.log2(n), 4),
        "total_seconds": round(stats.total_seconds, 6),
        "kdf_seconds": round(stats.kdf_seconds, 6),
        "forge_seconds": round(stats.forge_seconds, 6),
        "oracle_seconds": round(stats.oracle_seconds, 6),
        "keys_derived": stats.keys_derived,
        "max_ct_bytes": stats.max_ct_bytes,
        "peak_mem_bytes": peak,
        "recovered_ok": int(recovered == secret),
    }


def sweep(sizes, slow_max_n, seed) -> List[dict]:
    rows = []
    for n in sizes:
        for kdf_name in ("fast", "slow"):
            if kdf_name == "slow" and n > slow_max_n:
                continue  # keep slow-KDF runtime bounded
            print(f"  running N={n:6d} kdf={kdf_name} ...", flush=True)
            row = run_one(n, kdf_name, None, seed)
            assert row["recovered_ok"], f"attack failed at N={n} kdf={kdf_name}"
            rows.append(row)
    return rows


def split_sweep(n, splits, seed) -> List[dict]:
    rows = []
    for sp in splits:
        print(f"  split sweep N={n} split={sp} ...", flush=True)
        row = run_one(n, "fast", sp, seed)
        assert row["recovered_ok"]
        rows.append(row)
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"wrote {path}")


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def _to_num(rows, key, cast=float):
    return [cast(r[key]) for r in rows]


def make_figures():
    rows = read_csv(CSV_PATH)
    fast = [r for r in rows if r["kdf"] == "fast"]
    slow = [r for r in rows if r["kdf"] == "slow"]
    fast.sort(key=lambda r: int(r["N"]))
    slow.sort(key=lambda r: int(r["N"]))

    # Figure 1: queries vs N, compared to log2(N).
    plt.figure(figsize=(6, 4))
    Nf = _to_num(fast, "N", int)
    plt.plot(Nf, _to_num(fast, "queries", int), "o-", label="measured queries")
    plt.plot(Nf, _to_num(fast, "log2N"), "k--", label="log2(N)")
    plt.xscale("log")
    plt.xlabel("dictionary size N")
    plt.ylabel("oracle queries to recover")
    plt.title("Queries vs N (binary search tracks log2 N)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(FIGS, "fig1_queries_vs_N.png"), dpi=120)
    plt.close()

    # Figure 2: total time vs N, fast vs slow KDF.
    plt.figure(figsize=(6, 4))
    plt.plot(_to_num(fast, "N", int), _to_num(fast, "total_seconds"),
             "o-", label="fast KDF (SHA-256)")
    if slow:
        plt.plot(_to_num(slow, "N", int), _to_num(slow, "total_seconds"),
                 "s-", label="slow KDF (Argon2id)")
    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("dictionary size N")
    plt.ylabel("total recovery time (s)")
    plt.title("Attack wall-clock time: fast vs slow KDF")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(FIGS, "fig2_time_vs_N.png"), dpi=120)
    plt.close()

    # Figure 3: where the time goes (stacked) for the slow KDF (or fast if none).
    target = slow if slow else fast
    label = "slow KDF" if slow else "fast KDF"
    Ns = _to_num(target, "N", int)
    kdf_t = _to_num(target, "kdf_seconds")
    forge_t = _to_num(target, "forge_seconds")
    orac_t = _to_num(target, "oracle_seconds")
    plt.figure(figsize=(6, 4))
    plt.stackplot(Ns, kdf_t, forge_t, orac_t,
                  labels=["KDF", "forge (field maths)", "oracle"])
    plt.xscale("log")
    plt.xlabel("dictionary size N")
    plt.ylabel("time (s)")
    plt.title(f"Where the time goes ({label})")
    plt.legend(loc="upper left")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGS, "fig3_time_breakdown.png"), dpi=120)
    plt.close()

    # Figure 4: forged-ciphertext size vs split size.
    if os.path.exists(SPLIT_CSV_PATH):
        srows = read_csv(SPLIT_CSV_PATH)
        srows = [r for r in srows if r["split_size"] != "half"]
        srows.sort(key=lambda r: int(r["split_size"]))
        sp = _to_num(srows, "split_size", int)
        plt.figure(figsize=(6, 4))
        fig, ax1 = plt.subplots(figsize=(6, 4))
        ax1.plot(sp, _to_num(srows, "max_ct_bytes", int), "o-", color="tab:blue")
        ax1.set_xlabel("forge split size (keys per ciphertext)")
        ax1.set_ylabel("largest forged ciphertext (bytes)", color="tab:blue")
        ax1.tick_params(axis="y", labelcolor="tab:blue")
        ax2 = ax1.twinx()
        ax2.plot(sp, _to_num(srows, "queries", int), "s--", color="tab:red")
        ax2.set_ylabel("oracle queries", color="tab:red")
        ax2.tick_params(axis="y", labelcolor="tab:red")
        plt.title("Forged size & queries vs split size")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGS, "fig4_size_vs_split.png"), dpi=120)
        plt.close(fig)

    print(f"wrote figures to {FIGS}/")

    # Earn the headline sentence from the data.
    if slow:
        worst = max(slow, key=lambda r: int(r["N"]))
        print(
            "\nHeadline: ~log2(N) queries, but wall-clock is dominated by key "
            f"derivation. At N={worst['N']} the slow KDF already takes "
            f"{float(worst['total_seconds']):.1f}s "
            f"({float(worst['kdf_seconds']):.1f}s of it in Argon2); "
            "it scales ~linearly in N, so it becomes impractical within a small "
            "multiple of this N while the fast hash stays trivial."
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+",
                    default=[64, 128, 256, 512, 1024])
    ap.add_argument("--slow-max-n", type=int, default=256,
                    help="cap dictionary size for the slow KDF (runtime bound)")
    ap.add_argument("--split-n", type=int, default=512,
                    help="fixed N for the split-size sweep (figure 4)")
    ap.add_argument("--splits", type=int, nargs="+",
                    default=[1, 2, 4, 8, 16, 32, 64, 128])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--plot-only", action="store_true",
                    help="skip measurement, just redraw figures from CSV")
    args = ap.parse_args()

    os.makedirs(DATA, exist_ok=True)
    os.makedirs(FIGS, exist_ok=True)

    if not args.plot_only:
        print("sweeping dictionary size x KDF ...")
        rows = sweep(args.sizes, args.slow_max_n, args.seed)
        write_csv(CSV_PATH, rows)
        print("sweeping split size ...")
        srows = split_sweep(args.split_n, args.splits, args.seed)
        write_csv(SPLIT_CSV_PATH, srows)

    make_figures()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
