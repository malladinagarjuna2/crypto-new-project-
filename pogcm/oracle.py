"""The vulnerable demo server and its decryption oracle.

This is a stand-in for a real password-based system, built the UNSAFE way on
purpose so we can attack it and then show the fix. It is deliberately weak:

  * it uses a non-committing AEAD (plain AES-GCM),
  * it reuses a FIXED, public nonce (itself a misuse),
  * it leaks a single accept/reject bit.

The attacker never sees the real password; they only know the public candidate
list (e.g. a leaked-password dictionary) and can call :meth:`oracle`.
"""

from __future__ import annotations

from typing import Callable, Sequence

from . import gcm_internals as gi

# One fixed, public nonce used by the whole demo (96-bit / 12 bytes).
FIXED_NONCE = b"demo-nonce12"  # exactly 12 bytes
assert len(FIXED_NONCE) == 12

# Fixed, known plaintext / associated data so that only the key varies.
FIXED_PLAINTEXT = b"the password is correct\x00\x00\x00\x00\x00\x00\x00\x00\x00"
FIXED_AD = b""


class VulnerableServer:
    """A password-based server that answers decryption attempts with yes/no."""

    def __init__(
        self,
        real_password: str,
        candidates: Sequence[str],
        kdf: Callable[[str], bytes],
    ) -> None:
        if real_password not in candidates:
            raise ValueError("real_password must be in the candidate list")
        self._kdf = kdf
        self.candidates = list(candidates)
        # Derived once; the attacker does NOT see this.
        self.real_key = kdf(real_password)
        self._queries = 0
        # The stored secret: a genuine AES-GCM ciphertext under the real key.
        # (Not actually needed by the attack, but models a real stored blob.)
        self.stored = gi.compute_tag(
            self.real_key, FIXED_NONCE, FIXED_AD, FIXED_PLAINTEXT
        )

    def oracle(self, nonce: bytes, ct: bytes, tag: bytes) -> bool:
        """Attacker-facing endpoint.

        Tries to verify the SUBMITTED (nonce, ct, tag) under the server's real
        key and returns only True/False. This single accept/reject bit is the
        leak the partitioning attack exploits.
        """
        self._queries += 1
        return gi.verify_tag(self.real_key, nonce, FIXED_AD, ct, tag)

    def query_count(self) -> int:
        """Number of oracle calls so far (for measuring attack cost)."""
        return self._queries

    def reset_queries(self) -> None:
        self._queries = 0
