"""Committing-AEAD tests:

  (a) normal seal/open round-trips,
  (b) tampering is rejected,
  (c) the Module-2 forge can no longer produce one blob accepted under two
      different keys (the proof the fix works).

The PlainGCM baseline is included to confirm the attack DOES succeed against the
non-committing scheme — otherwise (c) would prove nothing.
"""

import hashlib
import os

import pytest

from pogcm import committing as cm
from pogcm import gcm_internals as gi
from pogcm import multicollision as mc

NONCE = bytes(12)
AD = b""
SCHEME_NAMES = list(cm.SCHEMES.keys())
COMMITTING_NAMES = [n for n in SCHEME_NAMES if cm.SCHEMES[n].committing]


@pytest.mark.parametrize("name", SCHEME_NAMES)
def test_roundtrip(name):
    s = cm.SCHEMES[name]()
    key = os.urandom(32)
    pt = b"attack at dawn, bring committing AEAD"
    blob = s.seal(key, NONCE, AD, pt)
    assert s.open(key, NONCE, AD, blob) == pt


@pytest.mark.parametrize("name", SCHEME_NAMES)
def test_tamper_rejected(name):
    s = cm.SCHEMES[name]()
    key = os.urandom(32)
    blob = bytearray(s.seal(key, NONCE, AD, b"hello world"))
    blob[0] ^= 0x01
    with pytest.raises(cm.CommittingError):
        s.open(key, NONCE, AD, bytes(blob))


@pytest.mark.parametrize("name", SCHEME_NAMES)
def test_wrong_key_rejected(name):
    s = cm.SCHEMES[name]()
    key = os.urandom(32)
    blob = s.seal(key, NONCE, AD, b"hello world")
    with pytest.raises(cm.CommittingError):
        s.open(os.urandom(32), NONCE, AD, blob)


def _adversary_blob(name, k1, k2):
    """Best single blob an attacker can build to open under both k1 and k2.

    The attacker uses the multicollision to make the underlying GCM tag valid
    under both keys, then fills any commitment field favouring k1.
    Returns the blob bytes.
    """
    ct_gcm, tag_gcm = mc.forge([k1, k2], NONCE, AD, mc.DEFAULT_TARGET_TAG)
    gcm_blob = ct_gcm + tag_gcm
    if name == "PlainGCM":
        return gcm_blob
    if name == "ZeroPrefix":
        # Attacker can only supply the GCM layer; the zero-prefix plaintext
        # check is out of their control.
        return gcm_blob
    if name == "HashCommit":
        return gcm_blob + cm.HashCommit._commit(k1)
    if name == "CTX":
        gcm_tag_k1 = gi.compute_tag(k1, NONCE, AD, ct_gcm)
        return ct_gcm + cm.CTX._ctx_tag(k1, NONCE, AD, gcm_tag_k1)
    if name == "EtMKeyBound":
        s = cm.EtMKeyBound()
        return gcm_blob + s._mac(k1, NONCE, AD, gcm_blob)
    raise AssertionError(name)


def _opens_count(name, blob, keys):
    s = cm.SCHEMES[name]()
    count = 0
    for k in keys:
        try:
            s.open(k, NONCE, AD, blob)
            count += 1
        except cm.CommittingError:
            pass
    return count


def test_baseline_attack_succeeds():
    # Sanity: the non-committing baseline IS breakable (blob opens under both).
    k1 = hashlib.sha256(b"k1").digest()
    k2 = hashlib.sha256(b"k2").digest()
    blob = _adversary_blob("PlainGCM", k1, k2)
    assert _opens_count("PlainGCM", blob, [k1, k2]) == 2


@pytest.mark.parametrize("name", COMMITTING_NAMES)
def test_forge_cannot_hit_two_keys(name):
    k1 = hashlib.sha256(b"k1").digest()
    k2 = hashlib.sha256(b"k2").digest()
    blob = _adversary_blob(name, k1, k2)
    # The committing fix must prevent one blob opening under two distinct keys.
    assert _opens_count(name, blob, [k1, k2]) <= 1
