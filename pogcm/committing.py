"""Key-committing AEAD wrappers (the fixes) plus a non-committing baseline.

Every scheme exposes the same interface:

    seal(key, nonce, ad, pt) -> blob          # bytes
    open(key, nonce, ad, blob) -> pt          # bytes, or raises on failure

A key-committing scheme binds a ciphertext to exactly one key, so the
multi-key ciphertext the partitioning attack relies on cannot exist.

Schemes implemented (all published constructions — cite in the report):

  * PlainGCM        — non-committing baseline (the vulnerable scheme).
  * ZeroPrefix      — Albertini et al., USENIX Security 2022 (padding fix).
  * HashCommit      — explicit SHA-256(key) commitment.
  * CTX             — Chan & Rogaway, ESORICS 2022 (commit via hashed tag).
  * EtMKeyBound     — Encrypt-then-HMAC with the key bound into the MAC.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Type

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK = 16
GCM_TAG = 16


class CommittingError(ValueError):
    """Raised when open() fails authentication or the key commitment check."""


class Scheme:
    """Base interface. ``overhead`` is extra bytes vs plain AES-GCM output."""

    name = "base"
    committing = False

    def seal(self, key: bytes, nonce: bytes, ad: bytes, pt: bytes) -> bytes:
        raise NotImplementedError

    def open(self, key: bytes, nonce: bytes, ad: bytes, blob: bytes) -> bytes:
        raise NotImplementedError


class PlainGCM(Scheme):
    """Non-committing baseline: raw AES-GCM. This is what the attack breaks."""

    name = "PlainGCM"
    committing = False

    def seal(self, key, nonce, ad, pt):
        return AESGCM(key).encrypt(nonce, pt, ad or None)

    def open(self, key, nonce, ad, blob):
        try:
            return AESGCM(key).decrypt(nonce, blob, ad or None)
        except Exception as e:  # noqa: BLE001
            raise CommittingError("auth failed") from e


class ZeroPrefix(Scheme):
    """Albertini et al. 2022: prepend a fixed zero block, check it on open.

    A forged multi-key ciphertext cannot keep the padding decrypting to all
    zeros under many keys, so the commitment holds. Overhead: one block.
    """

    name = "ZeroPrefix"
    committing = True
    PAD = b"\x00" * BLOCK

    def seal(self, key, nonce, ad, pt):
        return AESGCM(key).encrypt(nonce, self.PAD + pt, ad or None)

    def open(self, key, nonce, ad, blob):
        try:
            padded = AESGCM(key).decrypt(nonce, blob, ad or None)
        except Exception as e:  # noqa: BLE001
            raise CommittingError("auth failed") from e
        if not hmac.compare_digest(padded[:BLOCK], self.PAD):
            raise CommittingError("key-commitment (zero prefix) check failed")
        return padded[BLOCK:]


class HashCommit(Scheme):
    """Explicit commitment: append SHA-256(key) and verify on open.

    Overhead: 32 bytes.
    """

    name = "HashCommit"
    committing = True

    @staticmethod
    def _commit(key: bytes) -> bytes:
        return hashlib.sha256(b"pogcm-commit\x00" + key).digest()

    def seal(self, key, nonce, ad, pt):
        return AESGCM(key).encrypt(nonce, pt, ad or None) + self._commit(key)

    def open(self, key, nonce, ad, blob):
        body, commit = blob[:-32], blob[-32:]
        if not hmac.compare_digest(commit, self._commit(key)):
            raise CommittingError("key commitment mismatch")
        try:
            return AESGCM(key).decrypt(nonce, body, ad or None)
        except Exception as e:  # noqa: BLE001
            raise CommittingError("auth failed") from e


class CTX(Scheme):
    """Chan & Rogaway 2022 (CTX): replace the tag with H(key, nonce, ad, tag).

    The stored tag now depends on the key, so it cannot collide across keys.
    We keep the GCM ciphertext body and swap its 16-byte tag for a 32-byte
    commitment-bearing tag. Overhead vs plain AES-GCM: +16 bytes.
    """

    name = "CTX"
    committing = True

    @staticmethod
    def _ctx_tag(key, nonce, ad, gcm_tag) -> bytes:
        h = hashlib.sha256()
        h.update(b"pogcm-ctx\x00")
        for part in (key, nonce, ad, gcm_tag):
            h.update(len(part).to_bytes(8, "big"))
            h.update(part)
        return h.digest()  # 32 bytes

    def seal(self, key, nonce, ad, pt):
        full = AESGCM(key).encrypt(nonce, pt, ad or None)
        body, gcm_tag = full[:-GCM_TAG], full[-GCM_TAG:]
        return body + self._ctx_tag(key, nonce, ad or b"", gcm_tag)

    def open(self, key, nonce, ad, blob):
        body, ctx_tag = blob[:-32], blob[-32:]
        # Recover the GCM tag is impossible directly, so we recompute by
        # re-deriving: try all gcm tags is infeasible — instead we store enough
        # by recomputing the GCM tag from the body. We do that by decrypting
        # with a recomputed tag: here we instead recompute the expected ctx tag
        # by first getting the gcm tag via our own internals.
        from . import gcm_internals as gi

        # The GCM tag for this key/body is deterministic; recompute it.
        gcm_tag = gi.compute_tag(key, nonce, ad or b"", body)
        expected = self._ctx_tag(key, nonce, ad or b"", gcm_tag)
        if not hmac.compare_digest(ctx_tag, expected):
            raise CommittingError("CTX tag mismatch")
        # And confirm the body actually decrypts (tag now trusted).
        try:
            return AESGCM(key).decrypt(nonce, body + gcm_tag, ad or None)
        except Exception as e:  # noqa: BLE001
            raise CommittingError("auth failed") from e


class EtMKeyBound(Scheme):
    """Encrypt-then-HMAC with the key bound into the MAC.

    Standard EtM over the GCM blob, but the HMAC subkey is derived from the
    data key so the MAC commits to the key. Overhead: 32 bytes.
    """

    name = "EtMKeyBound"
    committing = True

    @staticmethod
    def _subkey(key: bytes) -> bytes:
        return hashlib.sha256(b"pogcm-mac-subkey\x00" + key).digest()

    def _mac(self, key, nonce, ad, body) -> bytes:
        m = hmac.new(self._subkey(key), digestmod=hashlib.sha256)
        for part in (nonce, ad, body):
            m.update(len(part).to_bytes(8, "big"))
            m.update(part)
        return m.digest()

    def seal(self, key, nonce, ad, pt):
        body = AESGCM(key).encrypt(nonce, pt, ad or None)
        return body + self._mac(key, nonce, ad or b"", body)

    def open(self, key, nonce, ad, blob):
        body, mac = blob[:-32], blob[-32:]
        if not hmac.compare_digest(mac, self._mac(key, nonce, ad or b"", body)):
            raise CommittingError("MAC mismatch")
        try:
            return AESGCM(key).decrypt(nonce, body, ad or None)
        except Exception as e:  # noqa: BLE001
            raise CommittingError("auth failed") from e


# Registry. PlainGCM first as the baseline.
SCHEMES: Dict[str, Type[Scheme]] = {
    "PlainGCM": PlainGCM,
    "ZeroPrefix": ZeroPrefix,
    "HashCommit": HashCommit,
    "CTX": CTX,
    "EtMKeyBound": EtMKeyBound,
}

# Theoretical overhead in bytes vs plain AES-GCM (tag-only) output.
OVERHEAD_BYTES = {
    "PlainGCM": 0,
    "ZeroPrefix": BLOCK,   # one extra plaintext block
    "HashCommit": 32,
    "CTX": 16,             # 32-byte tag replaces 16-byte tag
    "EtMKeyBound": 32,
}
