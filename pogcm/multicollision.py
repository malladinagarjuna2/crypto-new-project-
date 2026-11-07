"""Build one ciphertext valid under a chosen set of keys (the forge routine).

This follows Len-Grubbs-Ristenpart §3-§4. The GCM tag is linear in the
ciphertext blocks over GF(2^128):

    GHASH_{H_i}(A, C) = FixedPart_i  +  sum_j  C_j * H_i^{p_j}

For each target key K_i we want the tag to equal a chosen value T:

    T = GHASH_{H_i}(A, C) XOR S_i
    => sum_j C_j * H_i^{p_j}  =  (T XOR S_i) XOR FixedPart_i  =:  b_i

With l keys we get l linear constraints. Choosing exactly l ciphertext blocks
makes this a square (Vandermonde-type) system whose matrix is invertible as long
as the per-key subkeys H_i are distinct and non-zero — true with overwhelming
probability for distinct keys. Solving it yields one ciphertext of ~l blocks
that verifies under every K_i at once.

Cost is dominated by the linear solve, ~O(l^2..l^3) field ops with a plain
solver (the paper's O(l log^2 l) uses fast polynomial interpolation; for the
sizes we forge per query the plain solve is fine and easier to trust).
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from . import gcm_internals as gi
from . import gf128fast as ff

BLOCK = 16

# Default target tag/plaintext content. Any fixed value works; the oracle only
# checks the tag, so the per-key plaintext is irrelevant to the attack.
DEFAULT_TARGET_TAG = b"\x00" * BLOCK


def _fixed_part(key: bytes, nonce: bytes, ad: bytes, n_blocks: int) -> int:
    """GHASH contribution (as field int) with all ciphertext blocks zero."""
    return gi.fixed_part_zero_ct(key, ad, n_blocks)


def forge(
    keys: Sequence[bytes],
    nonce: bytes,
    ad: bytes = b"",
    target_tag: bytes = DEFAULT_TARGET_TAG,
) -> Tuple[bytes, bytes]:
    """Forge a (ct, tag) that verifies under every key in ``keys``.

    Returns (ciphertext_bytes, tag_bytes). The ciphertext has len(keys) blocks.
    """
    keys = list(keys)
    l = len(keys)
    if l == 0:
        raise ValueError("need at least one key")
    n = l  # one ciphertext block per key -> square (interpolation) system

    t_int = ff.bytes_to_int(target_tag)

    # For each key build the interpolation point (H_i, y_i) where we want the
    # ciphertext polynomial  P(x) = x^2 * Q(x)  to satisfy P(H_i) = b_i, i.e.
    # Q(H_i) = b_i * H_i^{-2}.  Here b_i = T XOR S_i XOR FixedPart_i.
    points: List[Tuple[int, int]] = []
    seen_h = set()
    for k in keys:
        h_int = ff.bytes_to_int(gi.hash_subkey(k))
        if h_int in seen_h:
            raise ValueError(
                "two keys produced the same GHASH subkey H; cannot forge "
                "(astronomically unlikely for distinct random keys)"
            )
        seen_h.add(h_int)
        s_int = ff.bytes_to_int(gi.tag_mask(k, nonce))
        fixed_int = _fixed_part(k, nonce, ad, n)
        b_i = t_int ^ s_int ^ fixed_int
        inv_h2 = ff.inv(ff.mul(h_int, h_int))
        y_i = ff.mul(b_i, inv_h2)
        points.append((h_int, y_i))

    # Q has degree n-1; its coefficients (lowest-first) map to ciphertext blocks.
    # Block j (power n-j+1) corresponds to Q's x^{n-1-j} coefficient, so the
    # ciphertext blocks are the coefficients in highest-first order.
    coeffs = ff.interpolate_coeffs(points)  # lowest-first, length n
    blocks_int = coeffs[::-1]  # highest-first -> block 0 .. block n-1

    ct = b"".join(ff.int_to_bytes(c) for c in blocks_int)
    return ct, bytes(target_tag)


def verify_under(key: bytes, nonce: bytes, ad: bytes, ct: bytes, tag: bytes) -> bool:
    """Convenience: does (nonce, ad, ct, tag) verify under ``key``?"""
    return gi.verify_tag(key, nonce, ad, ct, tag)
