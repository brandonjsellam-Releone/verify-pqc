# Evidence Pack signer — public key transparency

*A durable, versioned record of the public keys TRELYAN Inc. uses to sign paid Evidence Packs, so a pack is
independently auditable even if the live endpoint is unreachable. PUBLIC key material only — the secret keyset is
never committed anywhere. This is not a certification; the signature attests integrity + origin, not accuracy.*

## Current signer (key set #1)

- **Algorithm:** ML-DSA-87 (FIPS 204) ∧ SLH-DSA-SHA2-256f (FIPS 205) — a hybrid AND-composition; both must verify.
- **ML-DSA-87 public-key fingerprint (SHA-256):** `938fcb7acf919c19015a367a1e7a9fbd7355d5b51b0a9414cbaa33cdc69a6379`
- **SLH-DSA-SHA2-256f public-key fingerprint (SHA-256):** `d3368122bf1a8576b031bab6ab81a94405beb2f453a7ad331243953f3bb418aa`
- **First in service:** July 2026.
- **Live source of the full key material:** `GET https://throndar.ai/api/v1/evidence-signer` (also on throndar.ai/status).
  The `signer.pub.json` shipped with every pack must match these fingerprints.

## How to verify a pack you received (offline)

```
npm i @trelyan/verify-pqc            # or clone github.com/brandonjsellam-Releone/verify-pqc (MIT)
pqevidence verify evidence-pack.json --pub signer.pub.json --require-hybrid
```
Then confirm `signer.pub.json`'s fingerprints equal the two SHA-256 values above (and/or the live endpoint). If they
match and `pqevidence verify` prints VERIFIED, the pack's grade and every finding are exactly as signed — any
alteration invalidates the signature. If the fingerprint does NOT match this record, treat the pack as untrusted.

## Rotation policy (append-only)

Key rotation is an owner L3 event. On rotation, a new "key set #N" block is APPENDED here (the old block is never
deleted — packs signed under a retired key remain verifiable against their historical fingerprint), the live
`/api/v1/evidence-signer` + `/status` are updated, and the change is noted with its date. There has been **no
rotation to date** (key set #1 is current).

| Key set | ML-DSA-87 fingerprint (first 16) | SLH-DSA fingerprint (first 16) | In service | Status |
|---|---|---|---|---|
| #1 | `938fcb7acf919c19` | `d3368122bf1a8576` | Jul 2026 | **current** |

## Trust model (honest)

- The signature proves the pack came from this key set and is unaltered. It does **not** make the underlying scan an
  audit, and it is **not** a certification. See the pack's own disclaimer.
- A buyer does not need to trust TRELYAN — the verifier is open-source (MIT) and the key is public here + at the live
  endpoint. Trust is replaced by verification.
- If this repository and the live endpoint ever disagreed on the current fingerprint, that is a signal to stop and
  contact TRELYAN Inc. before trusting a pack.
