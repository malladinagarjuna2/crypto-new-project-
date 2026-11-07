"""The forge routine must produce a ciphertext the REAL library accepts under
every target key and rejects under a key outside the set.
"""

import hashlib
import random

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pogcm import multicollision as mc

NONCE = bytes(12)


def _lib_accepts(key, nonce, ct, tag):
    try:
        AESGCM(key).decrypt(nonce, ct + tag, None)
        return True
    except Exception:
        return False


@pytest.mark.parametrize("l", [2, 4, 8])
def test_forge_accepted_under_every_key(l):
    keys = [hashlib.sha256(f"candidate-{i}".encode()).digest() for i in range(l)]
    ct, tag = mc.forge(keys, NONCE, b"", mc.DEFAULT_TARGET_TAG)
    assert len(ct) == 16 * l
    for k in keys:
        assert _lib_accepts(k, NONCE, ct, tag), "library should accept target key"


@pytest.mark.parametrize("l", [2, 4, 8])
def test_forge_rejected_under_outsider(l):
    keys = [hashlib.sha256(f"candidate-{i}".encode()).digest() for i in range(l)]
    ct, tag = mc.forge(keys, NONCE, b"", mc.DEFAULT_TARGET_TAG)
    outsider = hashlib.sha256(b"not-in-the-set").digest()
    assert not _lib_accepts(outsider, NONCE, ct, tag)


def test_forge_single_key():
    key = hashlib.sha256(b"solo").digest()
    ct, tag = mc.forge([key], NONCE, b"", mc.DEFAULT_TARGET_TAG)
    assert _lib_accepts(key, NONCE, ct, tag)


def test_duplicate_subkey_raises():
    key = hashlib.sha256(b"dup").digest()
    with pytest.raises(ValueError):
        mc.forge([key, key], NONCE, b"", mc.DEFAULT_TARGET_TAG)
