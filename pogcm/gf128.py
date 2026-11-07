"""GF(2^128) field helpers for AES-GCM.

GCM works in GF(2^128) with reduction polynomial  x^128 + x^7 + x^2 + x + 1.

The one subtlety that silently breaks everything if you get it wrong is GCM's
*bit-reflection* convention: GCM treats the first (leftmost) bit of a byte
string as the highest-degree coefficient of the polynomial, i.e. bits within
each byte are numbered the opposite way from the usual integer encoding. We map
a 16-byte block to a field element by reflecting the bits of the 128-bit value,
so that field multiplication here matches GHASH's definition in NIST SP 800-38D.

We use the `galois` package for the field arithmetic itself.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

import galois

# The GCM reduction polynomial: x^128 + x^7 + x^2 + x + 1.
# galois expects the integer whose set bits are the polynomial coefficients.
# x^128 + x^7 + x^2 + x + 1 = 2^128 + 2^7 + 2^2 + 2^1 + 2^0.
_IRREDUCIBLE_POLY_INT = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

# Build the field once. This is somewhat expensive, so we cache it at import.
GF = galois.GF(2**128, irreducible_poly=_IRREDUCIBLE_POLY_INT)


def _reflect_bits_128(value: int) -> int:
    """Reverse the 128 bits of ``value`` (bit i <-> bit 127-i)."""
    out = 0
    for i in range(128):
        if (value >> i) & 1:
            out |= 1 << (127 - i)
    return out


def bytes_to_field(block16: bytes) -> "GF":
    """Map a 16-byte GCM block to a field element, honouring bit-reflection."""
    if len(block16) != 16:
        raise ValueError(f"block must be 16 bytes, got {len(block16)}")
    value = int.from_bytes(block16, "big")
    reflected = _reflect_bits_128(value)
    return GF(reflected)


def field_to_bytes(elem: "GF") -> bytes:
    """Inverse of :func:`bytes_to_field`."""
    reflected = int(elem)
    value = _reflect_bits_128(reflected)
    return value.to_bytes(16, "big")


def interpolate(points: Sequence[Tuple["GF", "GF"]]) -> "galois.Poly":
    """Lagrange-interpolate a polynomial through ``points`` over GF(2^128).

    ``points`` is a sequence of (x, y) field-element pairs with distinct x.
    Returns a ``galois.Poly`` p such that p(x_i) = y_i for every point.
    """
    xs = GF([int(x) for x, _ in points])
    ys = GF([int(y) for _, y in points])
    if len(set(int(x) for x in xs)) != len(xs):
        raise ValueError("interpolation x-coordinates must be distinct")
    return galois.lagrange_poly(xs, ys)


def poly_eval(poly: "galois.Poly", x: "GF") -> "GF":
    """Evaluate ``poly`` at ``x`` (thin wrapper for readability)."""
    return poly(x)
