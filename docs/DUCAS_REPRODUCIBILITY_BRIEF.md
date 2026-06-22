# Falcon-on-Algorand — Reproducibility Brief

**For:** independent review (Léo Ducas) · **Scope:** Algorand **TestNet**, **unaudited** · **Authority:** the chain, not this page
**Maintained by:** TRELYAN (THRONDAR is TRELYAN's product) · MIT · repo `github.com/brandonjsellam-Releone/verify-pqc`

> This brief exists so the central claim is *re-checkable by you*, not asserted. Every number below is read
> from on-chain bytes or from the deployed bytecode; where I distinguish the Falcon submission spec from our
> own convention, the convention is flagged as ours. If a line here doesn't reproduce, that line is wrong —
> tell me which.
>
> **What "verified" means here (operational definition).** Throughout this brief, **"verified" / "accepted"
> = the AVM `falcon_verify` opcode returned `true` for `(data, sig, pk)` and gated a write-once box.** It
> attests *opcode acceptance of these bytes* — **not** EUF-CMA security of the scheme, and **not** that the
> signed `data` preimage equals the inscribed content (the exact `falcon_verify` `data` construction is still
> being pinned from the contract TEAL — see §5.2). I'm asking you to press on exactly that gap.

---

## 1. The claim, in one sentence
trelyan-pq's **deterministic Falcon-1024** signatures **were accepted by the live AVM `falcon_verify` opcode**
on Algorand TestNet, and the exact wire bytes the opcode accepted are documented and independently
re-derivable from public indexer data.

## 2. The fixed point — on-chain (app-ids are chain-assigned)
- **App `763809096`** — the trelyan-pq inscription app. A confirmed call passed `falcon_verify` and wrote a
  **write-once** record box. The vector is pinned at `kat/falcon1024_det.onchain.json`
  (`verified_txid SQEPDOZ4NKFTVNO56FZS2MQOGV7SPTBTFQS2H2LUASV7XW52WZDQ`, round `63958252`, TestNet).
- **App `764917520`** — a *second, independent* app. Per our STH-anchor record it anchored a commitment via
  `inscribe()` (txn `HII5Z3MONXKT6D4O5NGZ677DMMFW5BCMQVIUTFNN532O5KLBPLYQ`). **Honesty caveat:** the kit ships
  **no golden KAT for this app yet** (only the `763809096` vector is pinned), so treat the second-app
  `falcon_verify` gating as *re-confirm-it-yourself* — `python onchain_probe.py --app 764917520` — not as a
  settled second data point. I'll pin a second KAT before leaning on it.
- The verdict is gated on the **chain-assigned app-ids** (`763809096` / `764917520`): an attacker cannot
  present their own app as TRELYAN's.
- The box-written / `verified_txid` / round facts above are **live chain state reported here** — re-check them
  with the §4 commands against ≥2 indexers; the chain is the authority, this page only reports.

## 3. The wire format — observed, not asserted
- **Transport:** signature and public key are ABI dynamic `byte[]` app-args — `uint16_be(len) || payload`.
  The 2-byte prefix is computed from length, **not a constant** (golden sig arg begins `04 d4` = 1236).
- **Decoded signature:** `header(1) || body(variable)`. **Header = `0xBA`.** **No fixed total length, no zero-pad.**
  Golden on-chain sig is **1236 B**; the bundled template vector is **1175 B** — a signer that hard-codes
  "exactly 1236" is non-conformant.
- **Public key:** **1793 B**, `pk[0] == 0x0A` (`0x00 | logn 10`) — the Falcon-1024 public-key format from the
  Falcon submission spec.

#### What is from the Falcon spec vs. what is ours (stated plainly — this is where I previously over-claimed)
- `0xBA = 0x3A | 0x80`. **`0x3A` is the Falcon-1024 COMPRESSED header as defined in the Falcon Round-3
  *submission specification* (Prest et al.)** — not a NIST-published standard (NIST has not standardized Falcon;
  the only forthcoming standard is FIPS 206 / FN-DSA, see below). In `0x3A`, high-nibble `0x3` = compressed,
  low-nibble `0xA` = logn 10. On the live wire byte `0xBA` the format is read as a **bit-field**: bits 4–6
  (mask `0x70`) `= 0x30` ⇒ compressed; **bit 7 (`0x80`) is read separately as our det-flag** — so I do *not*
  describe `0xBA` as "high-nibble `0x3`".
- **The `0x80` high bit and the following `0x00` version byte are trelyan-pq's deterministic-wrapper
  convention — a project extension, NOT a Falcon-submission or FIPS 206 (FN-DSA) field.** I do **not** call
  `0xBA` "the FN-DSA header." (`FIPS 206 (FN-DSA)` is not yet finalized as of this writing and defines neither.)
- **Salt — open item, flagged.** In our deterministic mode **no 40-byte salt is present on the wire** (the
  header is immediately followed by the compressed body, consistent with the 1236-B vector). For verification
  to succeed the nonce must be deterministically reconstructable from the signed data, since Falcon binds it via
  the challenge `c = H(r ‖ m)`. **The exact derivation rule and the `falcon_verify` `data` preimage are
  trelyan-pq convention and are NOT yet pinned in this brief** (the KAT's `_message_note` says as much). This is
  precisely §5.2 / the shared-KAT (Check B) item I want you to attack. Note: our tooling *infers* salt-absence
  from the `0x80` flag (a heuristic), it does not parse a salt field — so that inference only holds for
  trelyan-pq-shaped signatures.

#### On length bounds (the `≤1232` vs `≤1423` question)
- The **deployed contract** (app `763809096`) strips only the 2-byte ABI prefix (`extract 2 0`) and asserts
  `len(sig) ≤ 1423` (`pushint 1423; <=; assert`); the bytes reach `falcon_verify` unmodified. **`1423` is not
  arbitrary — it is `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE` for logn 10.** *(This describes the deployed
  bytecode; the TEAL is not bundled in the repo — §4 says how to fetch + disassemble it to confirm.)*
- The **AVM opcode itself performs no signature-length gate**: go-algorand `opFalconVerify` does an *exact
  public-key length check* (1793 B) and verifies the **compressed signature directly**. There is **no `≤1232`
  check** anywhere; `CTSignatureSize` (= **1538 B** for det1024, *not* 1232) is defined in the C library but is
  not applied as an input gate in the opcode/verify path. The only sig-length cap is the contract's `≤1423`.
- The disputed `1232` originates as a tighter annotation in the other signer's stack (an algo-pqc-kit
  `[1232]byte`-style cap), **not** from any Falcon-1024 constant (det1024: CT-size = 1538, compressed-max = 1423,
  pk = 1793). Since the on-chain golden sig is **1236 B (> 1232)**, a `≤1232` rule would reject a signature the
  chain demonstrably accepts.

## 4. Reproduce it (copy-paste; offline + a live check)
```bash
git clone https://github.com/brandonjsellam-Releone/verify-pqc && cd verify-pqc

./run-tests.sh                  # whole suite: core unit + KAT + SDK + anchor + live conformance

# or piecewise:
python falcon_interop.py kat kat/falcon1024_det.onchain.json     # validate the golden vector (offline)
PQC_SKIP_LIVE=1 node packages/verify-pqc/test.js                 # SDK unit (offline)
node packages/verify-pqc/test.js                                 # SDK + live on-chain check
python onchain_probe.py --app 763809096 \                        # dump the real bytes hitting falcon_verify
    --indexer https://testnet-idx.algonode.cloud
```
**Two honesty notes so the live checks aren't oversold:**
- `onchain_probe.py` implements **Level A** — it reads the app-arg the caller *passed* and ABI-decodes it.
  The **Level B** dryrun/simulate TEAL trace ("what the opcode *consumed*") is the gold standard but is **not
  shipped** — it's the manual check I'm recommending *you* run.
- The "contract strips only `extract 2 0`, no `extract 1/3`/`substring` on the sig" claim is **read from the
  deployed bytecode and is not reproduced from repo contents** (no TEAL/disassembly is bundled). To confirm it
  yourself: `algod GET /v2/applications/763809096` → base64-decode `approval-program` → disassemble (tealdbg /
  algosdk) → grep for `pushint 1423`, `<=`, `assert`, `extract 2 0`, and the *absence* of `extract 1/3` /
  `substring` on the signature arg.
- The KAT validator checks `pk` length, `header_byte`, `sig_len`, `deterministic` against the actual `sig_hex`
  — it does **not** require any fixed total length (the 1236-B and 1175-B vectors both validate).

## 5. What I'd most like you to attack
1. **Soundness of "accepted."** Can a green verdict be produced for bytes an attacker controls? Verdicts gate on
   recognized app-ids (`763809096`/`764917520`); an earlier adversarial review found + fixed **four false-verify
   entry points — one shared root cause across the three on-chain verifiers (a heuristic trusted on an arbitrary
   app-id), plus a distinct anchor-commitment bug** — and a regression test asserts an unrecognized app does
   **not** verify. *Known limits I'm not hiding:* the SDK **infers** acceptance from an `i_` box on a recognized
   app — **it does not re-run `falcon_verify` locally**, and the box→`falcon_verify` gating rests on the TEAL
   premise in §4 (which you must confirm from the deployed bytecode). On the anchor path specifically, a green
   verdict is **Layer-2-only** and does *not* re-attest the Layer-1 ML-DSA signed-tree-head signature.
2. **Header / salt handling — the open item.** Is the `0x80`+`0x00` wrapper described correctly, and — the real
   question — is the deterministic nonce/salt derivation sound? It is **not yet pinned** (§3); this is where I
   most want your eyes.
3. **The reconcile with algo-pqc-kit.** Two independent signers, same key+message → should be byte-identical.
   `falcon_interop.py compare` localizes a diff to {header, salt, body} — but note its salt-region attribution
   is unreliable when both inputs are deterministic (it keys off our `0x80` flag), so a genuine salt-handling
   divergence can be mislabeled "body" until the preimage + `r`-derivation are published. Is the KAT methodology
   adequate, and what would you require to call Check B conclusive?

## 6. Scope & residual risks (not pretended away)
- **TestNet, unaudited** — no external security/crypto audit yet (standing #1 action). Nothing implies MainNet readiness.
- **Single-indexer trust** — verifiers reflect one indexer's view; cross-check ≥2 or self-host for assurance.
- **Local trust premise** — the box→`falcon_verify` gating is read from deployed TEAL not bundled here (§4); the
  Level-B opcode-consumption trace is not yet captured.
- **Second app un-pinned** — app `764917520` has no golden KAT yet (§2); the "independent app" point is
  re-confirm-it-live until pinned.
- **Historical anchor** predates receipt-capture, so its Layer-1 signed-tree-head signature isn't re-verifiable
  from stored data; future anchors capture the receipt.
- **Falcon is a signature scheme, not encryption** — this suite makes no confidentiality claim.
- *(Out of scope for this Falcon brief, noted for completeness: the in-browser ML-DSA page loads `@noble` from a
  CDN — see `DEFENSE.md`; it is load-bearing for nothing here.)*

## 7. Provenance
The golden KAT carries the confirmed `verified_txid` + network; the chain is the authority and this document
only *reports* observed values. App `763809096` is treated as immutable and off-limits — the kit only reads it
and never submits transactions to it.
