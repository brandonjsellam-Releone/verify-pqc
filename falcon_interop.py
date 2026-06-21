"""
falcon_interop.py — Falcon-1024 / Algorand `falcon_verify` interop conformance core.

A reusable, dependency-free toolkit for proving that two independent Falcon-1024
signers (e.g. TRELYAN's `algorand/falcon` C lib and algo-pqc-kit's `falcon-multisig`
Rust) emit byte-compatible signatures for the Algorand AVM `falcon_verify` opcode.

It does three things, all on raw bytes (no algosdk / no C lib needed here):

  1. inspect()  — parse a Falcon-1024 signature: header byte, deterministic flag,
                  degree (logn), inferred salt handling, body length.
  2. compare()  — diff two signatures (ideally over the SAME key+message) and report
                  the FIRST divergence + which region it falls in (header / salt / body).
                  Deterministic signatures over the same (key, message) MUST be
                  byte-identical — this is the conformance test.
  3. KAT I/O    — load / validate a shared golden-vector file (kat/*.json) so both
                  projects pin to one reference, with the on-chain txid that proves it.

Header-byte facts (verified vs go-algorand opFalconVerify + the deployed TEAL of
TestNet app 763809096 — NOT a standards claim):
  * Falcon-1024 COMPRESSED header (NIST Round-3) = 0x3A: high-nibble 0x3 = compressed,
    low-nibble 0xA = logn 10. THIS part is standard.
  * 0xBA = 0x3A | 0x80. The 0x80 high bit, plus a following 0x00 version byte, are
    trelyan-pq's WRAPPER convention marking deterministic signing. They are NOT NIST
    Round-3 Falcon or FIPS-206 (FN-DSA, still a draft) fields. Describe them as a
    project extension — never as "the FN-DSA header".
  * The AVM falcon_verify opcode accepts 0xBA because it does not gate on header
    semantics: go-algorand opFalconVerify length-checks only the 1793-byte pubkey and
    bounds the sig by CTSignatureSize (there is NO <=1232 check). The compressed decoder
    reads the header to recover logn, so the header is load-bearing — it must reach the
    opcode intact.
  * The deployed contract (app 763809096) strips ONLY the 2-byte ABI length prefix
    (extract 2 0) and asserts the decoded sig <= 1423 (pushint 1423); it never strips
    the 0xBA header. Measured on-chain signature = 1236 B (1236 > 1232).

NOTE on bounds: 1423 is THIS contract's enforced ceiling — not a NIST constant, not a
universal cap. Don't argue a magic max with anyone; let the KAT + on-chain acceptance be
the authority. This module REPORTS lengths; it doesn't assert a spec number.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Optional

# Falcon-1024 fixed sizes.
LOGN_1024 = 10
PUBKEY_LEN_1024 = 1793          # 1-byte header (0x00|logn) + 1792-byte h
SALT_LEN = 40                   # Round-3 random nonce/salt (omitted in det mode)

# Header bit layout.
DET_FLAG = 0x80                 # trelyan-pq deterministic-wrapper bit (project convention, NOT a NIST/FIPS-206 field)
FORMAT_MASK = 0x70
FMT_COMPRESSED = 0x30           # variable-length compressed
FMT_PADDED = 0x50               # fixed-length padded
LOGN_MASK = 0x0F


@dataclass
class SigInfo:
    """Structured read of a Falcon signature's wire bytes."""
    total_len: int
    header_hex: str
    logn: int
    deterministic: bool
    fmt: str                    # "compressed" | "padded" | f"unknown(0x..)"
    salt_present: bool          # heuristic: randomized compressed carries a 40-B salt
    body_len: int               # bytes after header (and salt, if present)
    notes: str

    def as_dict(self) -> dict:
        return asdict(self)


def inspect(sig: bytes) -> SigInfo:
    """Parse a Falcon-1024 signature's structure from its raw bytes."""
    if not sig:
        raise ValueError("empty signature")
    h = sig[0]
    logn = h & LOGN_MASK
    deterministic = bool(h & DET_FLAG)
    fmt_bits = h & FORMAT_MASK
    fmt = {FMT_COMPRESSED: "compressed", FMT_PADDED: "padded"}.get(fmt_bits, f"unknown(0x{fmt_bits:02x})")
    # Heuristic: randomized compressed sigs carry an explicit 40-byte salt after the
    # header; Algorand-deterministic omits it (re-derives from the message at verify).
    salt_present = (fmt == "compressed") and (not deterministic)
    overhead = 1 + (SALT_LEN if salt_present else 0)
    notes = []
    if logn != LOGN_1024:
        notes.append(f"logn={logn} (expected 10 for Falcon-1024)")
    if h == 0xBA:
        notes.append("0xBA = 0x3A|0x80: standard Falcon-1024 compressed (0x3A) + trelyan-pq deterministic-wrapper bit (0x80); the 0x80 + a 0x00 version byte are a project convention, NOT a NIST/FIPS-206 field")
    elif h == 0x3A:
        notes.append("0x3A = standard compressed Falcon-1024 (NIST Round-3), randomized")
    if deterministic and salt_present:
        notes.append("WARN: deterministic flag set but salt assumed present — verify salt handling")
    return SigInfo(
        total_len=len(sig),
        header_hex=f"0x{h:02x}",
        logn=logn,
        deterministic=deterministic,
        fmt=fmt,
        salt_present=salt_present,
        body_len=len(sig) - overhead,
        notes="; ".join(notes) or "ok",
    )


def abi_decode_bytes(arg: bytes) -> bytes:
    """Strip an Algorand ABI dynamic `byte[]` 2-byte big-endian length prefix, if present.
    On-chain app-args are ABI-encoded: a Falcon sig arrives as len(2) || sig. The opcode
    receives the DECODED value, so always decode before inspecting the real header byte.
    Returns the inner bytes when the prefix matches the remaining length, else `arg` as-is."""
    if len(arg) >= 2:
        declared = int.from_bytes(arg[:2], "big")
        if declared == len(arg) - 2:
            return arg[2:]
    return arg


@dataclass
class CompareResult:
    identical: bool
    len_a: int
    len_b: int
    first_diff_offset: Optional[int]   # None if identical (up to min length)
    diff_region: Optional[str]         # "header" | "salt" | "body" | "length"
    summary: str


def compare(sig_a: bytes, sig_b: bytes, *, same_key_and_message: bool = True) -> CompareResult:
    """Diff two signatures. For DETERMINISTIC signers over the SAME (key, message),
    a conformant pair MUST be byte-identical; the first divergence localizes the
    encoding mismatch to {header bit, salt handling, compressed body}."""
    ia, ib = inspect(sig_a), inspect(sig_b)
    n = min(len(sig_a), len(sig_b))
    first = next((i for i in range(n) if sig_a[i] != sig_b[i]), None)

    def region(off: Optional[int]) -> Optional[str]:
        if off is None:
            return None if len(sig_a) == len(sig_b) else "length"
        if off == 0:
            return "header"
        if ia.salt_present and 1 <= off < 1 + SALT_LEN:
            return "salt"
        return "body"

    reg = region(first)
    identical = (first is None) and (len(sig_a) == len(sig_b))
    if identical:
        summary = "IDENTICAL — signers are byte-compatible for this vector."
    elif same_key_and_message:
        bits = []
        if ia.header_hex != ib.header_hex:
            bits.append(f"header {ia.header_hex} vs {ib.header_hex} (det flag {ia.deterministic} vs {ib.deterministic})")
        if ia.salt_present != ib.salt_present:
            bits.append(f"salt handling differs (A salt={ia.salt_present}, B salt={ib.salt_present})")
        if len(sig_a) != len(sig_b):
            bits.append(f"length {len(sig_a)} vs {len(sig_b)}")
        bits.append(f"first byte diff at offset {first} in the {reg} region")
        summary = "DIVERGE — " + "; ".join(bits)
    else:
        summary = ("Different bytes — but not flagged as same (key,message), so a diff is "
                   "expected for RANDOMIZED signers. Re-run with a deterministic vector.")
    return CompareResult(
        identical=identical, len_a=len(sig_a), len_b=len(sig_b),
        first_diff_offset=first, diff_region=reg, summary=summary,
    )


# --------------------------------------------------------------------------- #
# Shared KAT (golden vector) — the single reference both projects pin to.
# --------------------------------------------------------------------------- #
KAT_SCHEMA_FIELDS = (
    "scheme", "signer", "message_hex", "pubkey_hex", "sig_hex",
    "header_byte", "sig_len", "deterministic", "verified_txid", "network", "notes",
)


def load_kat(path: str) -> dict:
    """Load + structurally validate a golden-vector KAT file."""
    with open(path, "r", encoding="utf-8") as f:
        kat = json.load(f)
    missing = [k for k in KAT_SCHEMA_FIELDS if k not in kat]
    if missing:
        raise ValueError(f"KAT missing fields: {missing}")
    sig = bytes.fromhex(kat["sig_hex"])
    pk = bytes.fromhex(kat["pubkey_hex"])
    info = inspect(sig)
    problems = []
    if len(pk) != PUBKEY_LEN_1024:
        problems.append(f"pubkey {len(pk)}B != {PUBKEY_LEN_1024}")
    if info.header_hex != kat["header_byte"]:
        problems.append(f"header {info.header_hex} != declared {kat['header_byte']}")
    if info.total_len != kat["sig_len"]:
        problems.append(f"sig_len {info.total_len} != declared {kat['sig_len']}")
    if bool(kat["deterministic"]) != info.deterministic:
        problems.append(f"deterministic {info.deterministic} != declared {kat['deterministic']}")
    kat["_validation"] = {"ok": not problems, "problems": problems, "inspected": info.as_dict()}
    return kat


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "compare":
        a = bytes.fromhex(open(sys.argv[2]).read().strip())
        b = bytes.fromhex(open(sys.argv[3]).read().strip())
        print(json.dumps(compare(a, b).__dict__, indent=2))
    elif len(sys.argv) >= 3 and sys.argv[1] == "inspect":
        print(json.dumps(inspect(bytes.fromhex(open(sys.argv[2]).read().strip())).as_dict(), indent=2))
    elif len(sys.argv) >= 3 and sys.argv[1] == "kat":
        v = load_kat(sys.argv[2])["_validation"]
        print(json.dumps(v, indent=2))
        sys.exit(0 if v["ok"] else 1)
    else:
        print("usage: falcon_interop.py [inspect <sig.hex> | compare <a.hex> <b.hex> | kat <kat.json>]")
