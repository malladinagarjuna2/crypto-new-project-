#!/usr/bin/env python3
"""End-to-end attack demo: recover one planted password from the local oracle.

This is the correctness gate for the whole project. It plants a known password
in the vulnerable server, runs the partitioning attack, and asserts the
recovered value equals the secret. LOCAL DEMO ONLY.

    python experiments/run_attack_demo.py [--n 1000] [--kdf fast|slow] [--seed 0]
"""

from __future__ import annotations

import argparse
import math
import os
import random
import sys

# Allow running as a script from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pogcm import kdf as kdfs
from pogcm.attack import AttackStats, recover_password
from pogcm.oracle import VulnerableServer


def make_candidates(n: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    # Deterministic synthetic dictionary; the attack never uses the ordering.
    cands = [f"password{i:07d}" for i in range(n)]
    rng.shuffle(cands)
    return cands


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000, help="dictionary size")
    ap.add_argument("--kdf", choices=["fast", "slow"], default="fast")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--split", type=int, default=None, help="forge split size")
    args = ap.parse_args()

    random.seed(args.seed)
    kdf = kdfs.KDFS[args.kdf]
    candidates = make_candidates(args.n, args.seed)
    secret = random.Random(args.seed + 1).choice(candidates)

    server = VulnerableServer(secret, candidates, kdf)

    stats = AttackStats()
    recovered = recover_password(
        server, candidates, kdf, split_size=args.split, stats=stats
    )

    ok = recovered == secret
    print(f"dictionary size N      : {args.n}")
    print(f"KDF                    : {args.kdf}")
    print(f"planted secret         : {secret}")
    print(f"recovered password     : {recovered}")
    print(f"MATCH                  : {ok}")
    print(f"oracle queries         : {stats.queries}  (log2 N = {math.log2(args.n):.1f})")
    print(f"keys derived           : {stats.keys_derived}")
    print(f"largest forged ct bytes: {stats.max_ct_bytes}")
    print(
        f"time: kdf={stats.kdf_seconds:.3f}s "
        f"forge={stats.forge_seconds:.3f}s oracle={stats.oracle_seconds:.4f}s"
    )

    assert ok, "ATTACK FAILED: recovered password does not match the secret"
    print("\nOK: attack recovered the planted password end-to-end.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
