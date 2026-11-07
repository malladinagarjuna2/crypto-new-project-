#!/usr/bin/env python3
"""Contribution A: benchmark the committing fixes and prove each blocks the attack.

For every scheme we record encrypt/decrypt throughput and ciphertext-size
overhead, and run the attack-fails check: point the Module-2 forge at the scheme
and confirm it can no longer build one blob accepted under two different keys.
The non-committing PlainGCM baseline is included to show the attack DOES work
when the scheme is not committing.

    python experiments/benchmark_fixes.py

Outputs data/fixes.csv, prints a comparison table, and draws a size-overhead
bar chart into figures/.
"""

from __future__ import annotations

import csv
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from pogcm import committing as cm
from pogcm import gcm_internals as gi
from pogcm import multicollision as mc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
FIGS = os.path.join(ROOT, "figures")
CSV_PATH = os.path.join(DATA, "fixes.csv")

NONCE = bytes(12)
AD = b""
MSG_SIZE = 256 * 1024  # 256 KiB payload for throughput
ITERS = 40


def throughput(scheme, key, pt):
    # warm up
    blob = scheme.seal(key, NONCE, AD, pt)
    scheme.open(key, NONCE, AD, blob)

    t0 = time.perf_counter()
    for _ in range(ITERS):
        blob = scheme.seal(key, NONCE, AD, pt)
    enc_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(ITERS):
        scheme.open(key, NONCE, AD, blob)
    dec_s = time.perf_counter() - t0

    mb = (len(pt) * ITERS) / (1024 * 1024)
    return mb / enc_s, mb / dec_s, len(blob)


def adversary_blob(name, k1, k2):
    """Best single blob an attacker can craft to open under both k1 and k2."""
    ct_gcm, tag_gcm = mc.forge([k1, k2], NONCE, AD, mc.DEFAULT_TARGET_TAG)
    gcm_blob = ct_gcm + tag_gcm
    if name in ("PlainGCM", "ZeroPrefix"):
        return gcm_blob
    if name == "HashCommit":
        return gcm_blob + cm.HashCommit._commit(k1)
    if name == "CTX":
        gcm_tag_k1 = gi.compute_tag(k1, NONCE, AD, ct_gcm)
        return ct_gcm + cm.CTX._ctx_tag(k1, NONCE, AD, gcm_tag_k1)
    if name == "EtMKeyBound":
        return gcm_blob + cm.EtMKeyBound()._mac(k1, NONCE, AD, gcm_blob)
    raise AssertionError(name)


def attack_blocked(name):
    """True iff the forge can no longer hit two keys at once under this scheme."""
    k1 = hashlib.sha256(b"adv-k1").digest()
    k2 = hashlib.sha256(b"adv-k2").digest()
    blob = adversary_blob(name, k1, k2)
    scheme = cm.SCHEMES[name]()
    opened = 0
    for k in (k1, k2):
        try:
            scheme.open(k, NONCE, AD, blob)
            opened += 1
        except cm.CommittingError:
            pass
    return opened <= 1, opened


def main() -> int:
    os.makedirs(DATA, exist_ok=True)
    os.makedirs(FIGS, exist_ok=True)

    key = hashlib.sha256(b"bench-key").digest()
    pt = os.urandom(MSG_SIZE)

    # Plain AES-GCM output size for the same plaintext = len(pt) + 16 (tag).
    plain_len = MSG_SIZE + 16

    rows = []
    for name in cm.SCHEMES:
        scheme = cm.SCHEMES[name]()
        enc, dec, blob_len = throughput(scheme, key, pt)
        blocked, opened = attack_blocked(name)
        rows.append({
            "scheme": name,
            "committing": int(cm.SCHEMES[name].committing),
            "encrypt_MBps": round(enc, 1),
            "decrypt_MBps": round(dec, 1),
            "overhead_bytes": blob_len - plain_len,
            "stated_overhead_bytes": cm.OVERHEAD_BYTES[name],
            "attack_blocked": "yes" if blocked else "no",
            "keys_opened_by_forge": opened,
        })

    fields = list(rows[0].keys())
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {CSV_PATH}\n")

    # Comparison table.
    hdr = (f"{'scheme':12} {'commit':6} {'enc MB/s':>9} {'dec MB/s':>9} "
           f"{'overhead B':>10} {'attack blocked':>14}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['scheme']:12} {('yes' if r['committing'] else 'no'):6} "
              f"{r['encrypt_MBps']:9} {r['decrypt_MBps']:9} "
              f"{r['overhead_bytes']:10} {r['attack_blocked']:>14}")

    # Overhead bar chart.
    names = [r["scheme"] for r in rows]
    overheads = [r["overhead_bytes"] for r in rows]
    colors = ["tab:red" if r["attack_blocked"] == "no" else "tab:green"
              for r in rows]
    plt.figure(figsize=(6, 4))
    plt.bar(names, overheads, color=colors)
    plt.ylabel("ciphertext overhead vs plain AES-GCM (bytes)")
    plt.title("Committing-AEAD size overhead (green = attack blocked)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGS, "fig5_fix_overhead.png"), dpi=120)
    plt.close()
    print(f"\nwrote {os.path.join(FIGS, 'fig5_fix_overhead.png')}")

    # Caveat for an honest report.
    print(
        "\nNote: CTX.open recomputes the GCM tag via this demo's pure-Python "
        "GHASH, so its decrypt figure reflects that, not an optimized CTX "
        "(the other schemes use the library's C-speed GHASH in both "
        "directions). CTX's committing property and overhead are what the "
        "comparison is really about."
    )

    # Recommendation.
    committing_rows = [r for r in rows if r["committing"]
                       and r["attack_blocked"] == "yes"]
    best = min(committing_rows, key=lambda r: r["overhead_bytes"])
    print(
        f"\nRecommendation: {best['scheme']} — smallest overhead "
        f"({best['overhead_bytes']} bytes), simple, and it blocks the attack. "
        "General lesson (LGR): standardise on committing AEAD rather than "
        "bolting GCM onto password-based systems."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
