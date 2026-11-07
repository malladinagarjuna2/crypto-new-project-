"""pogcm — Partitioning Oracle on AES-GCM (educational demo).

Defensive, educational package that reproduces the Len-Grubbs-Ristenpart
(USENIX Security 2021) partitioning-oracle attack against a *self-contained,
deliberately-weak* demo, measures when it stops being practical, and
implements/benchmarks key-committing fixes.

Everything runs locally against a demo we wrote. No real system is attacked.
"""

__all__ = [
    "gf128",
    "gcm_internals",
    "multicollision",
    "oracle",
    "attack",
    "committing",
    "kdf",
]
