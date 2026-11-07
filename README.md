# Partitioning Oracle on AES-GCM — reproduce, measure, fix

A self-contained, **defensive/educational** cryptography project. It reproduces
the partitioning-oracle attack of **Len, Grubbs & Ristenpart (USENIX Security
2021)** against a *deliberately-weak demo we wrote*, measures when the attack
stops being practical, and implements & benchmarks key-committing fixes.

> **Scope & ethics.** Everything runs locally against `pogcm/oracle.py`, a demo
> written to be attackable. No real system or third party is involved. The
> deliverable is the defence: a drop-in committing-AEAD wrapper plus evidence of
> which fix to use. `pogcm/attack.py` is for this local demo only and must never
> be pointed at anything but `oracle.py`.

## What's here

Three results, presented as one story:

1. **Reproduce** — recover a password from the demo via a binary search powered
   by multi-key ("multicollision") ciphertexts, without ever knowing the key.
2. **Measure (contribution B)** — how attack cost (oracle queries, wall-clock,
   ciphertext size) grows with dictionary size, and where it becomes impractical.
3. **Compare fixes (contribution A)** — four committing AEAD constructions
   benchmarked for speed & size, each proven to block the attack.

The attack itself is **not new** (the paper did it). Ours is the practicality
curve and the side-by-side fix comparison with a recommendation.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.11+.

## Run

```bash
# 1. Correctness gate: recover one planted password end-to-end.
python experiments/run_attack_demo.py --n 1024 --kdf fast

# 2. Contribution B: practicality sweep -> data/*.csv + figures/fig1..4.
python experiments/measure_practicality.py
python experiments/measure_practicality.py --plot-only   # redraw from CSV only

# 3. Contribution A: benchmark the fixes + prove each blocks the attack.
python experiments/benchmark_fixes.py

# Tests (build/verify the maths first — the GHASH gate is here).
python -m pytest -q
```

## How the attack works (one paragraph)

AES-GCM is **not key-committing**: its tag is a polynomial in the key, so one
ciphertext can be forged to pass the tag check under *many* chosen keys at once
(`pogcm/multicollision.py`). The verify equation is linear in the ciphertext
blocks over GF(2¹²⁸), so forging for ℓ keys is a polynomial interpolation
through ℓ points. The demo server (`pogcm/oracle.py`) leaks one accept/reject
bit per decryption attempt. The driver (`pogcm/attack.py`) forges a ciphertext
valid under half the candidate passwords and asks the oracle: "accept" ⇒ the
real password is in that half. Each query halves the pool, so ~log₂(N) queries
pin it down.

## Repo layout

```
pogcm/
  gf128.py          GF(2^128) field helpers (galois) + bit-reflection
  gf128fast.py      fast pure-int GF(2^128) for the forge hot path + GHASH
  gcm_internals.py  H = AES_K(0), S = AES_K(J0), GHASH, tag recompute
  multicollision.py forge one ciphertext valid under a set of keys
  oracle.py         the vulnerable demo server + its decryption oracle
  attack.py         dictionary partitioning / binary-search driver (DEMO ONLY)
  committing.py     the fixes: ZeroPrefix, HashCommit, CTX, EtMKeyBound
  kdf.py            password -> key (fast SHA-256 / slow Argon2id)
experiments/        run_attack_demo, measure_practicality, benchmark_fixes
tests/              gf128, multicollision, oracle, committing
figures/  data/     generated PNGs and CSVs (+ sample_passwords.txt)
```

## Key results

- **Queries ≈ log₂(N)**, measured not assumed (`figures/fig1_queries_vs_N.png`).
- **The KDF is the lever.** With a fast hash the attack is trivial; with Argon2id
  (~90 ms/derivation here) wall-clock is dominated by deriving a key per
  candidate, so it scales ~linearly in N and becomes impractical quickly
  (`fig2`, `fig3`). The exact crossover is printed by the measurement script and
  depends on your machine's Argon2 cost.
- **Fixes** (`figures/fig5_fix_overhead.png`, `data/fixes.csv`):

  | scheme | committing | overhead vs plain GCM | blocks attack |
  |---|---|---|---|
  | PlainGCM (baseline) | no | 0 | **no** |
  | ZeroPrefix (Albertini+ 2022) | yes | +16 B | yes |
  | HashCommit (SHA-256(key)) | yes | +32 B | yes |
  | CTX (Chan–Rogaway 2022) | yes | +16 B | yes |
  | EtMKeyBound | yes | +32 B | yes |

  **Recommendation:** the **ZeroPrefix** padding fix — smallest overhead, simple,
  and it blocks the attack. General lesson (LGR): standardise on committing AEAD
  rather than bolting GCM onto password-based systems.

> Note: `CTX.open` recomputes the GCM tag via this demo's pure-Python GHASH, so
> its *decrypt* throughput is a demo artifact, not representative of an optimized
> CTX. Its committing property and size overhead are the point of the comparison.

## Honesty / notes for the report

- The fixed, public nonce in the demo is itself a misuse; it makes the
  multicollision maths cleanest. The committing fix is what actually removes the
  danger regardless of nonce handling.
- These fixes stop the *partitioning* attack specifically. The broader lesson is
  to use standardised committing AEAD for password-based systems.
- Reproducibility: seeds are fixed, versions pinned in `requirements.txt`, and
  every figure regenerates from a CSV (`--plot-only`).

## References

- Len, Grubbs & Ristenpart. *Partitioning Oracle Attacks.* USENIX Security 2021.
- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg. *How to Abuse and Fix
  Authenticated Encryption Without Key Commitment.* USENIX Security 2022.
- Chan & Rogaway. *On Committing Authenticated Encryption (CTX).* ESORICS 2022.
- Grubbs, Lu & Ristenpart. *Message Franking via Committing AE.* CRYPTO 2017.
- Bellare & Hoang. *Efficient Schemes for Committing AE.* EUROCRYPT 2022.
- NIST SP 800-38D (GCM); McGrew & Viega, *GCM.* INDOCRYPT 2004.
