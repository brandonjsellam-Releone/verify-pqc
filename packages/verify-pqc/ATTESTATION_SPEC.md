# TRELYAN Attestation Spec — `pqseal` + `pqattest`

*Auditor-facing specification of the multi-family signing primitive (`pqseal`) and the composed attestation (`pqattest`). Reference, DRAFT. The cryptographic primitives are the independently-audited [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and `@noble/curves`; `pqseal`/`pqattest` are the **composition layer** and are **not yet third-party-audited**. This document states what is constructed, what is verified, the threat model, and — explicitly — what is **not** claimed.*

---

## 1. Goals

Bind an arbitrary artifact (e.g. a signed PQC Migration Evidence Pack) to four independently-verifiable assurances, such that none can be downgraded after the fact:

| Assurance | "Proves" | Provided by |
|---|---|---|
| **WHO** | a set of independent keys, across distinct algorithm families, jointly signed it | `pqseal` (N-of-N multi-family signature) |
| **WHEN** | it existed no later than time *T*, per a threshold of timestamp authorities | `pqtsa` (PQ timestamp + multi-TSA threshold) |
| **WHERE-LOGGED** | it was entered into a specific append-only Merkle tree state | RFC-6962 transparency log (`pqsign.PQTransparencyLog`) |
| **WITNESSED** *(optional)* | independent witnesses observed the *same* tree head (equivocation resistance) | `pqkt` witness co-signing |

**Non-goal:** legal effect. This is a technical attestation, **not** an eIDAS *qualified* timestamp (we are not an accredited QTSP) and **not** a court/admissibility determination.

---

## 2. `pqseal` — N-of-N multi-family signature

### 2.1 Construction
A registry maps an algorithm id → `{ sign, verify, kind }`:

| `alg` | `kind` | scheme |
|---|---|---|
| `ML-DSA-87` | `lattice` | FIPS 204 |
| `SLH-DSA-256f` | `hash-based` | FIPS 205 |
| `Ed25519` | `classical` | RFC 8032 (non-PQ; an interop leg) |

Every leg signs the **same** message, which commits to the full ordered key-set:

```
sealedMessage = utf8( canon({ v:'pqseal-1', suite, legs:[pub_hex … in order], payload_sha512 }) )
suite         = 'trelyan-seal/' + algs.join('+')          // e.g. trelyan-seal/ML-DSA-87+SLH-DSA-256f+Ed25519
payload_sha512= sha512(payloadBytes) (hex)
context       = 'trelyan-pqseal-v1'
```
**Domain separation per family:** ML-DSA-87 and SLH-DSA-256f take the context as a native parameter (FIPS 204/205 context). Ed25519 (RFC 8032 §5.1) has **no** native context parameter, so the context bytes are **prepended** to the message before signing — this is **prefix domain separation**, **not** the `Ed25519ctx` variant (RFC 8032 §5.1's ctx mode). Signer and verifier prepend identically.

`seal(payload, signers)` → `{ v, suite, payload_sha512, legs:[{alg, kind, pub_hex, sig_hex}] }`.

### 2.2 Why drop/swap/add of a leg is detected (no extra binding step)
Because each leg signs `legs:[pub_hex…in order]`, **any** change to the leg-set (removing a leg, swapping a leg's key, adding a leg) changes `sealedMessage`, which invalidates **every** remaining leg's signature. Verification also recomputes `suite` from the legs and rejects a mismatch. (Council-confirmed: DeepSeek attacks 1–3, 8–10 blocked.)

### 2.3 Verification (`openSeal`) — AND-composition
`verified = payloadOk ∧ suiteOk ∧ allLegsValid ∧ familiesOk ∧ anchoredOk ∧ pinnedPresent ∧ meetsPinned ∧ suiteMatch`

- `payloadOk`: `sha512(payload) == payload_sha512`.
- `allLegsValid`: every leg's signature verifies under its embedded `pub_hex` and the context.
- `trusted` (per-family pins): a pinned family must be **present, matching, and valid** (a dropped pinned family is **not** silently ignored — DeepSeek fix #1).
- `requireSuite` / `requireKinds` / `requirePinned`: caller-asserted policy (exact composition / family diversity / full anchoring).

### 2.4 Validity vs. trust (honest model)
With **no** pins, `verified` proves only **self-consistency** (signatures valid under the *embedded* keys) — **not** authenticity. Authenticity requires a trust anchor: pass `trusted` and check `fullyAnchored`, or set `requirePinned`. The result object always exposes `fullyAnchored` / `suiteMatch` so a caller cannot mistake self-consistency for trust.

---

## 3. `pqattest` — composed attestation

### 3.1 Construction (order matters: **seal last**)
```
h512 = sha512(artifactBytes)   // STRONG artifact binding (~256-bit quantum collision resistance) — the seal binds this
h256 = sha256(artifactBytes)   // secondary; only the TSA token's native content_sha256 field
tst  = pqtsa.timestamp({content_sha256:h256}, tsa₀);  every extra TSA cosignTimestamp(tst, …)  // WHEN (threshold)
{index,entry} = pqtsa.anchor(log, tst);  inclusion = log.inclusion(index);  sth = log.signedTreeHead(logSk)  // WHERE
witness_cosigs = witnesses.map(w => w.cosign(sth, logPub))           // WITNESSED (optional)
binding = canon({ v:'pqattest-1', policy_id,
                  artifact_sha512:h512, artifact_sha256:h256,
                  tst_sha512: sha512(canon(tst)),                    // full tst incl. ALL cosigners
                  sth_sha512: sha512(canon(sth)),                    // the exact tree state
                  anchor_index, min_tsa, min_witness, seal_suite })
seal = pqseal.seal(binding, signers)                                 // WHO — countersigns everything above
```

- **`min_tsa`** = the number of distinct trusted TSAs the verifier must see (the anchored threshold). **`min_witness`** = the number of distinct trusted witness co-signatures required. Both are **bound in the seal**, so neither can be lowered after signing. **"Threshold PQ timestamp"** = a timestamp token co-signed by ≥ `min_tsa` distinct TSAs.

The **critical** design decision (10-seat council review, unanimous): the seal is computed **last**, over a composite that commits to the timestamp, the tree head, and **both thresholds**. This is the Sigstore "countersign the signature, not the artifact" pattern. Binding all components to a shared `artifact_sha256` alone would be **insufficient** — it would permit swapping in a different, equally-valid timestamp/log entry for the same hash (a downgrade).

### 3.2 Verification (`verifyAttest`) — AND-composition
```
verified = hashOk ∧ tstBindOk ∧ timestampOk ∧ anchorOk ∧ witnessOk ∧ sealOk
```
- `hashOk`: `sha256(artifact) == artifact_sha256`.
- `tstBindOk`: `tst.content_sha256 == artifact_sha256`.
- `timestampOk`: `verifyTimestampThreshold(tst, tsaPubs, min_tsa)` — ≥ `min_tsa` distinct **trusted** TSAs.
- `anchorOk`: STH signature valid under the pinned `logPub`; the RFC-6962 Merkle inclusion proof verifies, with the **leaf recomputed from the logged entry** (the anchored timestamp-token entry — **not** the artifact hash as the leaf) and `inclusion.tree_size` bound to the signed STH's `tree_size`.
- `witnessOk`: if `min_witness > 0`, ≥ `min_witness` distinct **trusted** witnesses co-signed *this* STH.
- `sealOk`: the seal verifies over the **recomputed** `binding` (so a swap of tst / sth / threshold / policy / index / suite breaks it).

### 3.3 Downgrade resistance (the "0-downgrade" property)
Because `binding` includes `sha512(tst)`, `sha512(sth)`, `min_tsa`, and `min_witness`, and the seal signs `binding`:

| Attack | Why it fails |
|---|---|
| swap in a different same-hash TST | `sha512(tst)` changes → seal invalid |
| drop a TSA cosigner | `tst` changes → seal invalid; and `timestampOk` < `min_tsa` |
| swap the signed tree head | `sha512(sth)` changes → seal invalid |
| lower the threshold (`min_tsa` / `min_witness`) | sealed value → seal invalid |
| drop a witness cosig | `witnessOk` < sealed `min_witness` → fails |
| tamper the artifact | `hashOk` / `tstBindOk` fail |

All six are **demonstrated** by `node pqattest.mjs` (14 test cases) under the assumptions in §4. This is a test-based demonstration, **not** a formal proof or a third-party audit; the reduction "breaking pqattest ⇒ breaking an underlying primitive" is argued informally, not machine-checked.

---

## 4. Threat model

**Adversary may:** reorder/drop/duplicate components; substitute any single valid component for another valid one of the same content hash; present an inclusion proof from a forked or smaller tree; supply malformed/adversarial input to any verifier.

**Adversary may not (assumed):** break ML-DSA-87, SLH-DSA-256f, Ed25519, SHA-256/512, or the canonicalization's injectivity over the (hex/fixed-string) inputs; compromise a **pinned** key.

**Trust roots are the verifier's responsibility.** Authenticity holds only against correctly pinned `trusted` seal keys, `tsaPubs`, `logPub`, and (if witnessed) `trustedWitnessPubs`. Equivocation resistance requires ≥ `k` honest, independent witnesses.

**Key-secrecy assumption.** Integrity depends on the **ongoing confidentiality** of *all* private keys — the seal signing keys, the log key, every trusted TSA key, and every witness key. Compromise of any of these permits forging or repudiating the corresponding component. (Listing only "revocation" as out-of-scope would understate this — it is a standing assumption, not just a reactive gap.)

**Hash-strength note.** The artifact is bound by **SHA-512** (`artifact_sha512`), giving ~256-bit quantum collision resistance. The secondary `artifact_sha256` exists only to populate the TSA token's native `content_sha256` field; its ~85-bit quantum collision bound does **not** weaken the attestation, because the seal binds the SHA-512 value (a SHA-256 collision that swapped the artifact would fail the SHA-512 `hashOk` and the seal).

**Out of scope (residual / future):** STH freshness windows and consistency-proof monitoring across observations (the witness layer mitigates equivocation but pqattest does not itself enforce a monotonic-checkpoint policy); key revocation/rotation; replay of a *static* artifact (add a nonce/validity-window at the application layer if freshness is required); side-channel/constant-time behavior of the composition (a third-party + SCA audit is being pursued).

---

## 5. What is NOT claimed

⛔ "qualified" (eIDAS-reserved; not an accredited QTSP) · ⛔ "maximal" / "military-grade" / "unbreakable" · ⛔ legal / court-admissibility effect · ⛔ FIPS-140-3 validation (uses FIPS *algorithms*; the composition is unaudited) · ⛔ that Ed25519 is post-quantum (it is the classical interop leg).

**Honest one-liner:** *an artifact signed by N independent algorithm families, whose signature also countersigns a threshold post-quantum timestamp, an RFC-6962 transparency-log inclusion proof, and optional witness co-signatures — each verifiable offline against pinned keys, and provably resistant to component downgrade.*

---

## 6. Property → evidence map

| Property | Run |
|---|---|
| N-of-N anti-downgrade (drop/swap/add/pin/suite) | `node pqseal.mjs` (18) |
| pqseal field-binding (systematic) | `node tamper-binding.mjs` (scenario 9c) |
| Composite countersigning + the six downgrades fail | `node pqattest.mjs` (14) |
| Full stack on a real Evidence Pack (inspectable) | `node examples/demo/run-demo.mjs` |
| Fail-closed totality of verifiers | `node fuzz-robustness.mjs`, `node assurance-properties.mjs` |
| Domain separation (no shared context) | `node domain-separation.mjs` |

## 7. Crypto-agility / versioning
Add or rotate a signature family by registering it in `pqseal`'s `FAMILIES` table; existing envelopes are unaffected (their `suite` pins their composition). Format versions are explicit (`pqseal-1`, `pqattest-1`); a verifier rejects an unknown `v`. The `suite` string is bound into both the seal message and the `pqattest` composite, so an algorithm substitution is detectable.
