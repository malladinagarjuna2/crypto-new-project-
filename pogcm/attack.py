"""LOCAL DEMO ONLY — partitioning-oracle attack driver (never point at anything but oracle.py).

Binary search over a public candidate password list using the single accept/
reject bit from :class:`pogcm.oracle.VulnerableServer`. Each query forges a
ciphertext valid under one chunk of candidate keys; an "accept" tells us the
real password's key is in that chunk. About log2(N) queries pin it down.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from . import multicollision as mc
from .oracle import FIXED_AD, FIXED_NONCE, VulnerableServer


@dataclass
class AttackStats:
    """Cost accounting for one recovery run."""

    recovered: Optional[str] = None
    queries: int = 0
    kdf_seconds: float = 0.0
    forge_seconds: float = 0.0
    oracle_seconds: float = 0.0
    max_ct_bytes: int = 0
    keys_derived: int = 0

    @property
    def total_seconds(self) -> float:
        return self.kdf_seconds + self.forge_seconds + self.oracle_seconds


def recover_password(
    server: VulnerableServer,
    candidates: Sequence[str],
    kdf: Callable[[str], bytes],
    split_size: Optional[int] = None,
    nonce: bytes = FIXED_NONCE,
    ad: bytes = FIXED_AD,
    stats: Optional[AttackStats] = None,
) -> str:
    """Recover the real password by binary-searching the candidate list.

    ``split_size`` caps how many keys are packed into a single forged
    ciphertext (the query/compute trade-off). When None, each step forges for
    exactly half the remaining pool — the pure binary search (~log2(N) queries).
    When set, each step tests a chunk of up to ``split_size`` candidates; this
    trades more queries for cheaper per-query forging.
    """
    if stats is None:
        stats = AttackStats()

    # Simple KDF memoisation so sweeping doesn't re-derive the same key.
    key_cache: dict[str, bytes] = {}

    def derive(pw: str) -> bytes:
        k = key_cache.get(pw)
        if k is None:
            t0 = time.perf_counter()
            k = kdf(pw)
            stats.kdf_seconds += time.perf_counter() - t0
            stats.keys_derived += 1
            key_cache[pw] = k
        return k

    pool: List[str] = list(candidates)

    while len(pool) > 1:
        if split_size is None:
            half = pool[: len(pool) // 2]
        else:
            half = pool[: min(split_size, len(pool) - 0)]
            # Guarantee progress: never test the entire pool, or an "accept"
            # wouldn't shrink it. Cap chunk at len(pool)-1.
            if len(half) >= len(pool):
                half = pool[: len(pool) - 1]

        keys = [derive(pw) for pw in half]

        t0 = time.perf_counter()
        ct, tag = mc.forge(keys, nonce, ad, mc.DEFAULT_TARGET_TAG)
        stats.forge_seconds += time.perf_counter() - t0
        stats.max_ct_bytes = max(stats.max_ct_bytes, len(ct))

        t0 = time.perf_counter()
        accepted = server.oracle(nonce, ct, tag)
        stats.oracle_seconds += time.perf_counter() - t0
        stats.queries += 1

        if accepted:
            pool = half
        else:
            pool = pool[len(half):]

    stats.recovered = pool[0]
    return pool[0]
