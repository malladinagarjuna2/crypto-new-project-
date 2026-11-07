"""Fast standalone GF(2^128) arithmetic for the forge hot path.

The `galois` package is correct but its per-operation overhead on 0-d arrays
makes the O(l^2) interpolation inside :mod:`pogcm.multicollision` far too slow
for large key sets. This module implements the same field directly on Python
integers so the forge scales to hundreds of keys.

Representation matches galois: an element is an int in [0, 2^128) whose bit i is
the coefficient of x^i. The reduction polynomial is
x^128 + x^7 + x^2 + x + 1, whose low part (x^128 reduced) is 0x87.

Tested bit-for-bit against galois in tests/test_gf128.py.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

_RED = 0x87  # x^7 + x^2 + x + 1  (what x^128 reduces to)
_MASK128 = (1 << 128) - 1

# Byte-wise bit-reverse table for the fast GCM bit-reflection.
_REV8 = [int(f"{b:08b}"[::-1], 2) for b in range(256)]


def bytes_to_int(block16: bytes) -> int:
    """Map a 16-byte GCM block to its field-element integer (bit-reflected).

    Reflecting all 128 bits == reversing the byte order and reversing the bits
    within each byte. Matches galois's representation (see tests).
    """
    reflected = bytes(_REV8[block16[15 - j]] for j in range(16))
    return int.from_bytes(reflected, "big")


def int_to_bytes(value: int) -> bytes:
    """Inverse of :func:`bytes_to_int`."""
    raw = value.to_bytes(16, "big")
    return bytes(_REV8[raw[15 - j]] for j in range(16))


def _clmul(a: int, b: int) -> int:
    """Carryless (polynomial) multiply of two ints over GF(2)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
    return r


def mul(a: int, b: int) -> int:
    """Multiply two field elements modulo x^128 + x^7 + x^2 + x + 1."""
    x = _clmul(a, b)
    # Fold the >=128 part down twice (clmul(hi, 0x87) stays small).
    hi = x >> 128
    x = (x & _MASK128) ^ _clmul(hi, _RED)
    hi = x >> 128
    x = (x & _MASK128) ^ _clmul(hi, _RED)
    return x


def pow_(a: int, e: int) -> int:
    """Exponentiation by squaring."""
    r = 1
    while e:
        if e & 1:
            r = mul(r, a)
        a = mul(a, a)
        e >>= 1
    return r


def inv(a: int) -> int:
    """Multiplicative inverse via a^(2^128 - 2)."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^128)")
    return pow_(a, (1 << 128) - 2)


def batch_inv(vals: Sequence[int]) -> List[int]:
    """Invert many field elements using a single inv() (Montgomery's trick)."""
    n = len(vals)
    prefix = [1] * (n + 1)
    for i in range(n):
        prefix[i + 1] = mul(prefix[i], vals[i])
    acc = inv(prefix[n])
    out = [0] * n
    for i in range(n - 1, -1, -1):
        out[i] = mul(acc, prefix[i])
        acc = mul(acc, vals[i])
    return out


def interpolate_coeffs(points: Sequence[Tuple[int, int]]) -> List[int]:
    """Lagrange interpolation returning dense coefficients, lowest degree first.

    Given n points (x_i, y_i) with distinct x_i, return [c_0, ..., c_{n-1}] of
    the unique degree-<n polynomial p with p(x_i) = y_i, p(x) = sum_k c_k x^k.

    O(n^2) field multiplications with exactly ONE field inversion (via batched
    inversion of the Lagrange denominators), so it scales to hundreds of points.
    """
    n = len(points)
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    if n == 1:
        return [ys[0]]

    # Master polynomial M(x) = prod_i (x - x_i), highest-degree coeff first.
    # In GF(2), (x - x_i) == (x + x_i).
    M = [1]  # represents constant 1, highest-first
    for xi in xs:
        # multiply M by (x + xi): new = M shifted up (x*M) XOR xi*M
        new = [0] * (len(M) + 1)
        for idx, c in enumerate(M):
            new[idx] ^= c           # x * M  (shift: same index, higher degree)
            new[idx + 1] ^= mul(c, xi)
        M = new
    # M now has n+1 coeffs, highest-first, degree n.

    # Lagrange denominators d_i = prod_{j != i} (x_i - x_j).
    dens = []
    for i in range(n):
        d = 1
        xi = xs[i]
        for j in range(n):
            if j != i:
                d = mul(d, xi ^ xs[j])
        dens.append(d)
    inv_dens = batch_inv(dens)

    # Accumulate p(x) = sum_i y_i * inv_den_i * (M(x) / (x - x_i)).
    # Division of M by (x - x_i) via synthetic division (root = x_i), highest-first.
    result_hi = [0] * n  # degree n-1 polynomial, highest-first
    for i in range(n):
        scale = mul(ys[i], inv_dens[i])
        if scale == 0:
            continue
        xi = xs[i]
        # synthetic division: quotient q has n coeffs (degree n-1), highest-first
        q = [0] * n
        q[0] = M[0]
        for k in range(1, n):
            q[k] = M[k] ^ mul(xi, q[k - 1])
        for k in range(n):
            result_hi[k] ^= mul(scale, q[k])

    # Convert highest-first -> lowest-first dense coeffs of length n.
    return result_hi[::-1]
