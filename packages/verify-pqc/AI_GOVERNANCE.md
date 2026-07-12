# Verifiable AI Governance — a post-quantum, machine-checked stack

A cryptographic, **fail-closed** layer for AI governance, mapped to the four functions of the
[NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework). Each leg is a
**signed attestation** built on the `verify-pqc` post-quantum suite; a top-level record cross-binds the
legs to **one model**, a signed **policy** gates admission, an **evidence pack** makes the whole thing
independently re-verifiable, and a **transparency anchor** makes admissions publicly accountable.

> **Honest posture (read first).** This is a **self-attested, pre-audit** reference implementation. It
> proves **who signed what, and that the pieces are cryptographically consistent** — it does **not**
> certify a model, its safety, or its compliance, and it is **not** independently audited. It is not
> "quantum-safe" or "certified". FIPS 203/204/205 are final; **FIPS 206 (FN-DSA/Falcon) is a draft**.
> Every module states its own limits in its header; this document summarizes them.

---

## The stack → NIST AI RMF

| RMF function | Module | Attests (WHO signs → WHAT) | Self-test |
|---|---|---|---|
| **MAP** | `pqaibom` | the **declarant** → the AI Bill of Materials (models + training data) + a *Declaration-Assurance* grade | 53 |
| **MEASURE** | `pqeval` | the **evaluator** → an evaluation, bound to the AIBOM's model + a *posture* grade | 26 |
| **MANAGE** | `pqtrace` | the **runner** → a hash-chained execution/provenance trace, committing the model + inventory | 38 |
| *capstone* | `pqgovernance-record` | binds MAP ∧ MEASURE ∧ MANAGE to **one model** (three distinct signers) | 22 |
| *admission* | `pqgovernance-gate` | fail-closed CI gate over the record (grade/drift/distinct-signer policy) | 25 |
| **GOVERN** | `pqgovern-policy` | the **compliance owner** → a signed, versioned admission **policy** the gate enforces | 37 |
| *deliverable* | `pqgovern-evidence` | a self-contained **Evidence Pack** — the whole admission, independently re-verifiable | 15 |
| *transparency* | `pqgovern-anchor` | binds an admission into an **append-only RFC-6962 log** (public accountability) | 18 |
| *transparency* | `pqgovern-monitor` | a **fork-refusing** watcher: holds the log append-only across the STHs it sees | 20 |
| *transparency* | `pqgovern-witness` | a **multi-party quorum** that detects a log **equivocating** (split-view) | 18 |
| *CI command* | `pqgovern-cli` | a drop-in pipeline gate: pack + pins → **exit 0 (ADMIT) / 1 (BLOCK)** | 8 |

Composition is proven end-to-end two ways: **`pqgovern-e2e`** (by invocation, the governance modules through
their public APIs) and **`formal/pqgovern_admission_z3.py`** (a machine-checked Z3 proof of admission
soundness). See *Machine-checked proofs* below.

---

## What the composed guarantee is — precisely

A verifier who **pins the trusted public keys** (declarant, evaluator, runner, compliance owner) and runs
the admission gets, fail-closed:

- **One model.** The AIBOM, the eval, and the trace are all cross-bound to the same model weights hash —
  no leg can be about a different model (`pqgovernance-record`).
- **Owner-authenticated criteria.** Admission is enforced under a **signed** policy; an unpinned or
  attacker-signed policy can never admit (a config flag cannot disable authenticity), and the admission
  decision surfaces *which* signed policy (id/version/issuer) gated it (`pqgovern-policy`).
- **The verifier owns the trust.** The evidence pack and CLI carry **no trust and no verdict** — the
  admission is **always re-derived** under the verifier's own pins (`pqgovern-evidence`, `pqgovern-cli`).
- **Public accountability (optional).** An admission can be anchored into an append-only transparency
  log; anyone with the pinned log key can prove it was recorded and detect a log that rewrites history
  (`pqgovern-anchor`). A **fork-refusing monitor** holds the log append-only across the heads it observes
  (`pqgovern-monitor`), and a **multi-party witness quorum** detects a log that presents *different*
  histories to different parties — a split-view/equivocation a single monitor is structurally blind to
  (`pqgovern-witness`).

### What it is **not** (the load-bearing limits)

- **Attestation, not truth.** A signature proves *who* asserted a claim, **not that the claim is true** —
  a signed lie is possible. `pqeval` proves the evaluator signed a score, not that the benchmark ran;
  `pqaibom` proves the declared inventory, not that it is complete; `pqtrace` is **runner-attested log**
  provenance, not proof the model behaved that way.
- **Grades are computed, criteria are the owner's.** The Declaration-Assurance / posture grades are
  deterministic functions of the *declared* artifacts; the admission floor is whatever the owner *signed* —
  neither is a statement of adequacy for any regime.
- **Inclusion ≠ completeness.** A transparency anchor proves an admission was *recorded*, not that the log
  is *complete*. The witness quorum (`pqgovern-witness`) detects **equivocation** (the log showing conflicting
  histories) — a **safety** property, proven only among witnesses that gossip into the same reconcile; it does
  **not** prove **completeness/liveness** (a log that simply *withholds* an entry from everyone equally is a
  separate, unsolved-here availability problem).
- **Symbolic proofs.** The Z3 proofs are in a symbolic (Dolev-Yao / EUF-CMA) model of the decision logic;
  they are not computational reductions and do not prove the primitives themselves (those rest on
  FIPS 204/205; FIPS 206 is draft). They complement — never replace — tests, fuzzing, and external audit.

---

## Machine-checked proofs (Z3 SMT)

`python formal/run_all.py` runs the whole suite (**17/17**). Each proof shows the *negation is unsat* (no
counterexample in the model) plus a **teeth** control (a deliberately broken design → *sat*, proving the
harness discriminates and the property is load-bearing). Governance-relevant proofs:

- `pqgovern_admission_z3.py` — **admission soundness**: no ADMIT without an owner-authenticated policy, all
  three record legs owner-pinned + cross-bound, in-window, version-pinned, and the **signed** criteria met;
  and the caller cannot shadow those criteria. Non-vacuity check: the honest case still admits.
- `pqgovern_witness_z3.py` — **witness-quorum reconciliation soundness**: a quorum is reported `consistent`
  only when no witnesses fork *and* every different-size pair is proof-verified (a missing proof can never
  read as safe), and every designed fork is detected. Its teeth reproduce the exact pre-fix bug.
- `pqgovern_witnessed_z3.py` — **witnessed-admission composition**: an admission is `witnessed` only when it
  admits + anchors, a **k-of-n** distinct-witness quorum vouched for the head, and no fork was proven; teeth
  prove each gate (admit/anchor, threshold, no-equivocation) is load-bearing.
- `pqaibom_grade_cap_z3.py` — no unearned Declaration-Assurance grade (omission-gaming structurally capped).
- `pqeval_posture_cap_z3.py` — no top posture without an earned, registry-validated suite.
- `pqtrace_chain_z3.py` — the sealed head pins the entire step chain (any edit/reorder/truncate detectable).
- `pqai_provenance_binding_z3.py` — no BOM substitution in the AIBOM∧trace join.

(Plus the spine proofs: RFC-6962 inclusion/consistency, domain-separation, pqseal anti-downgrade, pqkt.)

---

## Quickstart

```js
import * as aibom  from './pqaibom.mjs';
import * as gov    from './pqgovernance-record.mjs';
import * as policy from './pqgovern-policy.mjs';
import * as ev     from './pqgovern-evidence.mjs';

// 1. three parties sign MAP ∧ MEASURE ∧ MANAGE, cross-bound to one model
const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, {
  aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner,
  assuranceLevel: aibom.ASSURANCE.bound, subject: 'my-model', suiteRegistry });

// 2. the compliance owner signs an admission policy (GOVERN)
const signedPolicy = policy.signPolicy(policy.buildPolicy({
  policy_id: 'prod-release', version: 3, effective_ts, expiry_ts, issuer: 'Compliance',
  criteria: { minAibomGrade: 'B', requireDistinctSigners: true, requireDriftChecked: true } }), owner);

// 3. bundle a self-contained, independently-verifiable Evidence Pack
const pack = ev.buildEvidencePack({ record, signedPolicy }, { packager: 'Release Eng', packSigners: packager });

// 4. a RELYING PARTY, with its OWN pinned keys, re-derives the verdict (no trust in the pack):
const verdict = ev.verifyEvidencePack(pack, {
  aibomSealOpts, evalSealOpts, traceSealOpts, policySealOpts, packSealOpts,
  suiteRegistry, loadedComponents, atTs, minVersion: 3, requireWindow: true, requireDistinctSigners: true });
console.log(verdict.admit ? 'ADMIT' : 'BLOCK');   // gate on `admit`, never on integrity
```

**In CI**, skip the code and use the gate command — exit 0 = admit, 1 = block:

```bash
node pqgovern-cli.mjs evidence-pack.json verifier-config.json
```

where `verifier-config.json` holds the verifier's own hex-encoded pinned keys, suite registry, and
window/version pins. See `pqgovern-cli.mjs` for the config shape.

---

## Reproducibility

```bash
node test-all.mjs                 # every module self-test (91 modules, expect ALL MODULES PASS)
python formal/run_all.py          # the machine-checked proof suite (expect 17/17)
```

## Cryptographic suite

Signing is **`pqseal`** — an N-of-N AND-composition (e.g. ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519) that is
crypto-agile and anti-downgrade; transparency uses the `pqsign` RFC-6962 log. All Cat-5 hybrid PQ.
`@noble/post-quantum` is not independently audited.

---

*Part of the `verify-pqc` SDK (`v0.28.0-draft`). Self-attested, pre-audit; "supports, not certifies".*
