"""Oracle behaviour and end-to-end recovery on a small dictionary."""

import math
import random

import pytest

from pogcm import kdf as kdfs
from pogcm.attack import AttackStats, recover_password
from pogcm.oracle import FIXED_AD, FIXED_NONCE, VulnerableServer
from pogcm import multicollision as mc


def _candidates(n):
    return [f"password{i:05d}" for i in range(n)]


def test_oracle_accepts_only_real_key():
    cands = _candidates(16)
    secret = cands[7]
    server = VulnerableServer(secret, cands, kdfs.key_from_password_fast)

    real_key = kdfs.key_from_password_fast(secret)
    ct, tag = mc.forge([real_key], FIXED_NONCE, FIXED_AD, mc.DEFAULT_TARGET_TAG)
    assert server.oracle(FIXED_NONCE, ct, tag) is True

    other_key = kdfs.key_from_password_fast(cands[0])
    ct2, tag2 = mc.forge([other_key], FIXED_NONCE, FIXED_AD, mc.DEFAULT_TARGET_TAG)
    assert server.oracle(FIXED_NONCE, ct2, tag2) is False


def test_recover_planted_password():
    n = 64
    cands = _candidates(n)
    secret = cands[41]
    server = VulnerableServer(secret, cands, kdfs.key_from_password_fast)
    stats = AttackStats()
    recovered = recover_password(
        server, cands, kdfs.key_from_password_fast, stats=stats
    )
    assert recovered == secret
    # Binary search over a power-of-two dictionary uses exactly log2(N) queries.
    assert stats.queries == int(math.log2(n))
    assert server.query_count() == stats.queries


def test_query_count_near_log2_non_power_of_two():
    n = 100
    cands = _candidates(n)
    secret = cands[57]
    server = VulnerableServer(secret, cands, kdfs.key_from_password_fast)
    recovered = recover_password(server, cands, kdfs.key_from_password_fast)
    assert recovered == secret
    assert server.query_count() <= math.ceil(math.log2(n))
