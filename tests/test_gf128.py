"""Field-layer and GHASH tests. A wrong field mapping silently breaks all else,
so these are the gate: do not trust the rest until GHASH matches a known answer.
"""

import os
import random

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pogcm import gcm_internals as gi
from pogcm import gf128
from pogcm import gf128fast as ff
from pogcm.gf128 import GF


def test_bytes_field_roundtrip():
    rng = random.Random(0)
    for _ in range(200):
        block = bytes(rng.randrange(256) for _ in range(16))
        assert gf128.field_to_bytes(gf128.bytes_to_field(block)) == block


def test_ghash_matches_library_tag_no_aad():
    # Encrypt with the real library, recompute the tag via our GHASH, compare.
    rng = random.Random(1)
    for _ in range(25):
        key = bytes(rng.randrange(256) for _ in range(32))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        pt = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 48)))
        full = AESGCM(key).encrypt(nonce, pt, None)
        ct, tag = full[:-16], full[-16:]
        assert gi.compute_tag(key, nonce, b"", ct) == tag


def test_ghash_matches_library_tag_with_aad():
    rng = random.Random(2)
    for _ in range(25):
        key = bytes(rng.randrange(256) for _ in range(32))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        ad = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        pt = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 48)))
        full = AESGCM(key).encrypt(nonce, pt, ad)
        ct, tag = full[:-16], full[-16:]
        assert gi.compute_tag(key, nonce, ad, ct) == tag


def test_nist_gcm_vector_case2():
    # NIST / McGrew-Viega GCM test case 2: all-zero key, nonce, and 16-byte pt.
    key = bytes(16)
    nonce = bytes(12)
    pt = bytes(16)
    full = AESGCM(key).encrypt(nonce, pt, None)
    ct, tag = full[:-16], full[-16:]
    assert ct.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    assert gi.compute_tag(key, nonce, b"", ct) == tag


def test_fastfield_matches_galois():
    rng = random.Random(3)
    for _ in range(100):
        a = rng.randrange(1, 2**128)
        b = rng.randrange(1, 2**128)
        assert ff.mul(a, b) == int(GF(a) * GF(b))
        assert ff.inv(a) == int(GF(a) ** -1)
        e = rng.randrange(0, 40)
        assert ff.pow_(a, e) == int(GF(a) ** e)


def test_fastfield_interpolation():
    rng = random.Random(4)
    for n in (1, 2, 5, 25):
        seen = set()
        pts = []
        while len(pts) < n:
            x = rng.randrange(1, 2**128)
            if x in seen:
                continue
            seen.add(x)
            pts.append((x, rng.randrange(0, 2**128)))
        coeffs = ff.interpolate_coeffs(pts)
        for x, y in pts:
            val = 0
            for k, c in enumerate(coeffs):
                val ^= ff.mul(c, ff.pow_(x, k))
            assert val == y
