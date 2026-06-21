# Falcon-on-Algorand interop conformance suite

**A reference and conformance suite for Falcon-1024 signers targeting the AVM
`falcon_verify` path exercised by Algorand TestNet application `763809096`.**

Version 0.2 (draft) · MIT · maintained by TRELYAN (commons-first PQC foundation).

---

## 0. Status & scope — read first

This is a **reference + conformance suite, not a standard.** It describes the *observed*
byte layout and acceptance behaviour of **one specific** on-chain verifier path — the
`falcon_verify` usage in Algorand **TestNet** application `763809096` — so that independent
Falcon-1024 signers can produce payloads that interoperate with it.

- **TestNet only · unaudited.** Nothing here implies MainNet behaviour or production readiness.
- **Falcon is a signature scheme, not encryption.**
- **The chain is the authority, not this document.** Where a length or byte value is stated,
  the authoritative source is the bytes that reached `falcon_verify` in a *confirmed* on-chain
  call (the golden KAT and its `verified_txid`). This document REPORTS observed values.
- **App `763809096` is treated as immutable and off-limits.** This suite describes it as
  deployed and never submits transactions to it (see Check C).
- It does **not** define, extend, or speak for any NIST, FIPS, or IETF specification.

## 1. Wire format (observed)

### 1.1 Transport — Algorand ABI `byte[]`
On the inscribe call, the signature and public key are each carried as an ABI dynamic
`byte[]` application argument: a **2-byte big-endian length prefix** followed by the raw bytes.

```
app_arg  =  uint16_be(len(payload)) || payload
```

The prefix is computed from the payload length; it is **not** a fixed constant. For the
golden vector the signature arg begins `04 d4` (= 1236) and the public-key arg begins
`07 01` (= 1793) — these are *examples for those payloads*, not universal values.

### 1.2 Decoded signature layout
After stripping the ABI prefix, the signature is **variable-length** and begins with a
single header byte:

```
sig  =  header(1) || body(variable)
```

- **`header = 0xBA`** for trelyan-pq's deterministic-compressed signatures.
- **No fixed total length.** The deployed contract enforces an **upper bound** only —
  `extract 2 0` then `pushint 1423; <=; assert`, i.e. `len(sig) ≤ 1423`. Real conformant
  vectors differ in length (the on-chain golden vector is **1236 B**; the template is
  **1175 B**). A signer or checker that hard-codes an equality (e.g. "exactly 1236") is
  non-conformant.
- The body is the standard Falcon-1024 compressed encoding (the `s2` short-vector data).
  It is **not** zero-padded to a fixed slot; the golden vector ends in non-zero bytes.

### 1.3 The header byte — what is standard, what is convention
```
0xBA = 0x3A | 0x80
       0x3A : standard Falcon-1024 COMPRESSED header (high-nibble 0x3 = compressed,
              low-nibble 0xA = logn 10).                        [NIST Round-3 Falcon]
       0x80 : a high bit trelyan-pq sets to mark DETERMINISTIC signing.   [convention]
```
A `0x00` version byte may follow as part of the wrapper. **The `0x80` bit and the `0x00`
version byte are trelyan-pq conventions — they are NOT NIST Round-3 Falcon or FIPS-206
(FN-DSA) fields.** FIPS 206 is a draft and defines neither. Do not call `0xBA` "the FN-DSA
header." In deterministic mode the 40-byte random salt of standard Falcon is **omitted**
(re-derived from the message at verification); there is no fixed salt field at a fixed offset.

### 1.4 How the opcode consumes it
The contract passes the decoded bytes to `falcon_verify` **unmodified** — it does not clear
`0x80`, drop the version byte, or pad/truncate. (Verified from the deployed approval program:
the only byte-removing op on the argument is `extract 2 0`, the ABI prefix strip; there is no
`extract 1`/`extract 3`/`substring` anywhere.) The AVM opcode length-checks only the public
key and bounds the signature by the C library's `CTSignatureSize`, not by 1232. The compressed
decoder reads the header to recover `logn`, so the header is load-bearing and must reach the
opcode intact.

### 1.5 Public key
1793 bytes, `pk[0] == 0x0A` (= `0x00 | logn 10`), followed by the packed polynomial `h`
(coefficient form). This matches the standard Falcon-1024 public-key size and header.

## 2. Golden KAT format

A KAT pins one reference vector. Required fields (`kat/*.json`):

| field | meaning |
|---|---|
| `scheme` | human label — **must not** imply FIPS-206/FN-DSA |
| `signer` | which signer produced it |
| `message_hex` | the bytes signed (document the exact preimage construction) |
| `pubkey_hex` | 1793-byte public key (`pk[0]=0x0a`) |
| `sig_hex` | decoded signature (`sig[0]=0xba`), variable length |
| `header_byte`, `sig_len`, `deterministic` | declared values, checked against `sig_hex` |
| `verified_txid`, `network` | the confirmed on-chain call that accepted these bytes |
| `notes` | provenance |

The validator (`falcon_interop.py load_kat`, `@trelyan/verify-pqc`) checks `pk` length,
`header_byte`, `sig_len`, and `deterministic` against the actual `sig_hex` — it does **not**
require any fixed total length.

## 3. The three conformance checks

- **Check A — on-chain byte inspection.** Pull a confirmed `falcon_verify` call from a public
  indexer; ABI-decode the signature; confirm `sig[0]=0xBA`, `logn=10`, `len ≤ 1423`, pubkey
  1793 B / `pk[0]=0x0A`. (`onchain_probe.py`, `verifyOnChain`.)
- **Check B — shared KAT byte-match.** A second signer reproduces a golden vector
  *byte-for-byte* from the same key + message. Mismatches localize to {header, body}.
  (`falcon_interop.compare`, `verify-pqc compareSigs`.) Document the message preimage and the
  deterministic salt derivation, or vectors mismatch for non-encoding reasons.
- **Check C — TestNet round-trip.** Each signer's output is accepted by `falcon_verify`
  on-chain. **Check C MUST target a separate sandbox application — never app `763809096`.**
  Submitting to `763809096` consumes a one-time write-once slot and mutates the protected
  app's state.

## 4. Normative requirements

- **N1.** Carry signature and public key as ABI `byte[]` (2-byte BE length prefix + payload).
- **N2.** Signature header MUST be `0xBA` (`0x3A | 0x80`); decoded `len ≤ 1423`; **no** fixed
  total length, **no** zero-padding.
- **N3.** Public key MUST be 1793 bytes with `pk[0] == 0x0A`.
- **N4.** Pass the decoded signature to `falcon_verify` unmodified (no header/version stripping).
- **N5.** A KAT `scheme`/metadata field MUST NOT contain "FN-DSA" or imply FIPS-206.
- **N6.** Conformance round-trips (Check C) MUST NOT be performed against app `763809096`.

## 5. References (informative)
- Algorand AVM `falcon_verify` opcode; `algorandfoundation/falcon-signatures`.
- go-algorand `opFalconVerify` (pubkey-only length check; bound = `CTSignatureSize`).
- NIST Round-3 Falcon (the standard parts: `0x3A` nibbles, 1793-B pubkey, `s2` body).
- The deployed reference: TestNet app `763809096`, golden vector `kat/falcon1024_det.onchain.json`.
