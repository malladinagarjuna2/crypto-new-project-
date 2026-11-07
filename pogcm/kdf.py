"""Password -> key derivation, in a fast (weak) and a slow (careful) variant.

The measurement section compares these: the KDF cost is the dominant lever on
whether the partitioning attack is practical, because the attacker must derive
one key per candidate password for every forged ciphertext.
"""

from __future__ import annotations

import hashlib

from argon2.low_level import Type, hash_secret_raw

# Fixed, public parameters so the demo is deterministic and reproducible.
# (In a real system the salt would be per-user and secret-ish; here everything
# about the scheme is public except *which* candidate is the real password.)
_ARGON2_SALT = b"pogcm-demo-fixed-salt--16b"[:16]
_ARGON2_TIME_COST = 2
_ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
_ARGON2_PARALLELISM = 1
KEY_LEN = 32


def key_from_password_fast(password: str) -> bytes:
    """A single SHA-256 of the password. Models a weak-but-common choice."""
    return hashlib.sha256(password.encode("utf-8")).digest()[:KEY_LEN]


def key_from_password_slow(password: str) -> bytes:
    """Argon2id with fixed salt/params. Models a careful choice."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=_ARGON2_SALT,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_KIB,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


# Convenience registry so experiments can select by name.
KDFS = {
    "fast": key_from_password_fast,
    "slow": key_from_password_slow,
}
