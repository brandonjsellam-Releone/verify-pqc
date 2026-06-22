# Falcon-on-Algorand — Reproducibility Brief

**For:** independent review (Léo Ducas) · **Scope:** Algorand **TestNet**, **unaudited** · **Authority:** the chain, not this page
**Maintained by:** TRELYAN (THRONDAR is TRELYAN's product) · MIT · repo `github.com/brandonjsellam-Releone/verify-pqc`

> This brief exists so the central claim is *re-checkable by you*, not asserted. Every number below is read
> from on-chain bytes or from the deployed bytecode; where I distinguish "standard" from "our convention",
> the convention is flagged as ours. If a line here doesn't reproduce, that line is wrong — tell me which.

---

## 1. The claim, in one sentence
trelyan-pq's **deterministic Falcon-1024** signatures verify through the **live AVM `falcon_verify` opcode**
on Algorand TestNet, and the exact wire bytes that the opcode accepts are documented and independently
re-derivable from public indexer data.

## 2. The fixed point — on-chain, twice (app-ids are unforgeable)
- **App `763809096`** — the trelyan-pq inscription app. A confirmed call passed `falcon_verify` and wrote a
  **write-once** record box. Golden vector pinned at `kat/falcon1024_det.onchain.json` with its `verified_txid`.
- **App `764917520`** — a *fresh* sandbox app where `falcon_verify` again gated a write-once inscription
  (txn `HII5Z3MO…`). Independent app ⇒ not a one-off quirk of the first contract.
- App-ids are chain-assigned and unforgeable, so "verified" is bound to a fact an attacker cannot mint.

## 3. The wire format — observed, not asserted
- **Transport:** signature and public key are ABI dynamic `byte[]` app-args — `uint16_be(len) || payload`.
  The 2-byte prefix is computed from length, **not a constant** (golden sig arg begins `04 d4` = 1236).
- **Decoded signature:** `header(1) || body(variable)`. **Header = `0xBA`.** **No fixed total length, no zero-pad.**
  Golden on-chain sig is **1236 B**; the template vector is **1175 B** — a signer that hard-codes "exactly 1236" is non-conformant.
- **Public key:** **1793 B**, `pk[0] == 0x0A` (`0x00 | logn 10`) — the standard Falcon-1024 pubkey size/header.

#### What is standard vs. what is ours (stated plainly — this is where I previously over-claimed)
- `0xBA = 0x3A | 0x80`. **`0x3A` is the standard NIST Round-3 Falcon-1024 COMPRESSED header** (high-nibble `0x3` = compressed, low-nibble `0xA` = logn 10).
- **The `0x80` high bit and the following `0x00` version byte are trelyan-pq's deterministic-wrapper convention — a project extension, NOT a NIST Round-3 Falcon or FIPS-206 (FN-DSA, still a draft) field.** I do **not** call `0xBA` "the FN-DSA header."
- In **deterministic mode the 40-byte salt is omitted** (re-derived from the message at verification); there is no fixed salt field at a fixed offset.

#### On length bounds (the `≤1232` vs `≤1423` question)
- The **deployed contract** (app `763809096`) strips only the 2-byte ABI prefix (`extract 2 0`) and asserts
  `len(sig) ≤ 1423` (`pushint 1423; <=; assert`). It never strips the `0xBA` header or the version byte —
  the bytes reach `falcon_verify` **unmodified**.
- The **AVM opcode itself has no signature-length gate**: go-algorand `opFalconVerify` length-checks only the
  1793-byte public key and bounds the signature by the C library's `CTSignatureSize`. **There is no `≤1232` check.**
  Since the measured sig is **1236 B (> 1232)**, a `≤1232` rule would reject signatures the chain accepts.

## 4. Reproduce it (copy-paste; offline + one live check)
```bash
git clone https://github.com/brandonjsellam-Releone/verify-pqc && cd verify-pqc

./run-tests.sh                  # whole suite: core unit + KAT + SDK + anchor + live conformance

# or piecewise:
python falcon_interop.py kat kat/falcon1024_det.onchain.json     # validate the golden vector
python onchain_probe.py --app 763809096 \                        # dump the real bytes hitting falcon_verify
    --indexer https://testnet-idx.algonode.cloud
PQC_SKIP_LIVE=1 node packages/verify-pqc/test.js                 # SDK unit (offline)
node packages/verify-pqc/test.js                                 # SDK + live on-chain check
```
- `onchain_probe.py` reads the app-arg the caller **passed**. For the gold standard ("what the opcode
  **consumed**"), a dryrun/simulate TEAL trace confirms no header strip — the deployed TEAL has no
  `extract 1/3` or `substring` on the signature arg (only the ABI `extract 2 0`).
- The KAT validator checks `pk` length, `header_byte`, `sig_len`, `deterministic` against the actual
  `sig_hex` — it does **not** require any fixed total length.

## 5. What I'd most like you to attack
1. **Soundness of "verified."** Can a green verdict be produced for bytes an attacker controls? (Verdicts are
   gated on recognized app-ids `763809096`/`764917520` and a real `inscribe()` call — adversarial review already
   found + fixed 4 false-verify paths; the regression test asserts an unrecognized app does **not** verify.)
2. **Header / salt handling.** Is the `0x80`+`0x00` wrapper described correctly, and is the deterministic
   salt-omission reasoning sound?
3. **The reconcile with algo-pqc-kit.** Two independent signers, same key+message → should be byte-identical.
   `falcon_interop.py compare` localizes any diff to {header, salt, body}. Is the KAT methodology adequate?

## 6. Scope & residual risks (not pretended away)
- **TestNet, unaudited** — no external security/crypto audit yet (standing #1 action). Nothing implies MainNet readiness.
- **Single-indexer trust** — verifiers reflect one indexer's view; cross-check ≥2 or self-host for assurance.
- **In-browser ML-DSA page** loads `@noble/post-quantum` from a CDN (`esm.sh`); the npm path is vendored — vendor before production.
- **Historical anchor** predates receipt-capture, so its Layer-1 signed-tree-head signature isn't re-verifiable from stored data; future anchors capture the receipt.
- **Falcon is a signature scheme, not encryption** — this suite makes no confidentiality claim.

## 7. Provenance
The golden KAT carries the confirmed `verified_txid` + network; the chain is the authority and this document
only *reports* observed values. App `763809096` is treated as immutable and off-limits — the kit only reads it
and never submits transactions to it.
