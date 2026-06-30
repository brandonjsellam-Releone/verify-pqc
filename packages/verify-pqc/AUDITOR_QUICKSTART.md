# Auditor Quickstart — TRELYAN PQ SDK

A cold-start path for an external crypto / side-channel auditor. Reference code, **unaudited**, not FIPS-140-3
validated, not constant-time. Node ≥18.

## Run everything (≈ minutes)
```bash
cd trelyan-interop/packages/verify-pqc
npm ci           # deterministic install from package-lock.json (@noble/post-quantum, @noble/hashes, @noble/ciphers, @noble/curves)
node test-all.mjs            # every module self-test + the four assurance harnesses (run node test-all.mjs → ALL MODULES PASS)
node kat-conformance.mjs     # deterministic NIST-style KATs (ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256s)
node spine-vectors.mjs       # PINNED transparency-spine vectors (must reproduce the hex)
node vectors-crosscheck.mjs  # 42,574-case differential vs an independent RFC-6962 reference
node fuzz-robustness.mjs     # negative/fuzz sweep (60 verifiers × 72 adversarial input classes = 4,320 calls) — asserts 0 fail-open + verifier totality
node conformance-vectors.mjs # Wave-2 cores KAT (25): pinned deterministic ids / did:trelyan / commitments reproduce from fixed seeds + round-trip & negatives (hedged ML-DSA/SLH sigs not byte-pinned)
node platform-conformance-vectors.mjs # platform engines KAT (19): pqmonitor/pqgate/pqflow/pqdelegate/pqconsentflow deterministic ids + policy_id/cert_id/receipt_id/ledger-head/parent_ref + round-trip & attenuation/violation negatives
node product-flows.mjs       # end-to-end product lifecycles through the real cores (Shield/Agent/Market/Consent) — 16 assertions
node tamper-binding.mjs      # signature-coverage — flips every signed field across the signing surface, asserts each is bound (1,064 assertions; covers all 12 of this session's signed cores incl. the 5 platform engines + 7 Wave-2 cores)
node domain-separation.mjs   # 0 bare sign/verify (191 sites), 65 distinct contexts, cross-context rejection
node canon-determinism.mjs   # canon() byte-identical across 28 modules + deterministic/injective
```
All four assurance harnesses (`fuzz-robustness`, `tamper-binding`, `domain-separation`, `canon-determinism`) plus the
differential validator run inside `test-all.mjs` too. They already caught + fixed 5 real signed-vs-checked / protocol
gaps (logged in `SECURITY_REVIEW.md`) — the auditor's job is to **confirm** these proofs are faithful, then focus on
side-channel/constant-time (the class the harnesses cannot cover).

## Read order
1. `AUDIT_DOSSIER.md` — scope, primitive inventory, **canonicalization**, the domain-separation **context registry**
   (all signing contexts verified distinct), the Merkle scheme.
2. `SPINE_SPEC.md` — formal spec of the transparency spine (leaf/node, inclusion §2.1.1, consistency §2.1.2, STH,
   consumer obligations) + the pinned conformance vectors. **This is the recommended first audit target** (it is the
   shared root of trust for pqtsa / pqkt / pqvault / pqinduct).
3. `THREAT_MODEL.md` — assets / adversaries / boundaries / per-asset threat → mitigation → residual.
4. `SECURITY_REVIEW.md` — the full multi-model council-review log (every finding, applied vs rejected-with-reason).
5. `ADVERSARY_MODEL.md` (capability→property→evidence) · `REPRODUCIBILITY.md` + `sbom.cdx.json` (deterministic build + deps).
   · `CANONICALIZATION_SPEC.md` (the signing serializer) · `SIGNED_OBJECTS.md` (signed-object call-graph inventory) ·
   `KEY_HANDLING.md` (key ownership / RNG / zeroization residual / supply chain).
6. `SDK.md` (catalog + test counts), `PACKAGING.md` (publishable-verifier vs held-SDK split), `AUDIT_RFP.md` (the engagement scope/SoW).

## Suggested scope priority (per the council's diligence flag)
Audit the **spine first** (pqsign Merkle/STH/inclusion/consistency) — everything else inherits its guarantees. Then
the hybrid handshake (pqtransport), the KEM envelope (polarseek), and the signature-context domain separation. The
50+ modules are breadth; the spine + the 4 primitives are the depth that matters. The Wave-2 product cores (pqshield /
pqcap / pqadmit / pqconsent / pqvc / pqfirmware / pqpay) are independent signed objects — each TOTAL/fail-closed, with
its capability→property→evidence row in `ADVERSARY_MODEL.md` and a KAT in `conformance-vectors.mjs`.

## What to focus on
- Second-preimage / domain-separation on leaf (`0x00`) vs node (`0x01`) bytes; index/tree_size binding; consistency
  edge cases (powers of two, m==n, m==1).
- Canonical-JSON determinism across languages (key ordering, number/string encoding) — signature stability depends on it.
- **Timing/side-channels** (out of scope of the reference; a primary audit deliverable).
- Consumer-obligation gaps (§6 of SPINE_SPEC): freshness/completeness needs witnesses (witness-service.mjs is the node).

## Known non-goals (documented, not findings to "discover")
Not constant-time; JSON not ASN.1/X.509 DER (pqpki); single-log completeness needs gossip; pqtsa is not an accredited
eIDAS QTSP; custody keys (polarseek/pqvault) are long-lived by design. See each module header + `AUDIT_DOSSIER.md §7`.
