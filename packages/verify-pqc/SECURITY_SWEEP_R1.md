# Full-portfolio adversarial security sweep — Round 1 (internal, pre-audit)

*Method: a 9-cluster multi-agent sweep over all 74 SDK modules — each cluster reviewed for concrete defects, each
candidate finding then **adversarially verified** (refute-by-default) by an independent agent, and every surviving
finding **adjudicated by direct code inspection** in the main loop before any fix. This records the honest disposition
of each. Self-attested internal assurance — NOT a third-party audit.*

**Outcome: 17 findings survived adversarial verification → 13 fixed, 4 rejected on inspection.** (Several more candidates
were refuted at the verify stage, incl. re-confirming the messenger's bidirectional ratchet-state model is sound.)

## Fixed (13)

| # | Sev | Module | Defect → fix |
|---|---|---|---|
| 1 | high | `pqx3dh` | One-time-prekey consumed *after* decapsulation → **consume-on-receipt** before decap (a throwing/failed attempt is no longer retryable; check→consume is one synchronous step). |
| 2 | high | `pqtransport` | `R_auth_ok` is true under TOFU → added **`R_trustAnchored`/`I_trustAnchored`** (sig-valid AND identity-pinned) so validity can't be misread as trust; production callers must pin. |
| 3 | med | `pqx3dh` | `verifyPrekeyBundle` accepted a bundle with the reserved `kem_ot_id='lastresort'` (silent SK divergence) → **rejected on verify** (matches publish-side guard). |
| 4 | **crit** | `pqsearch-server` | Empty index returned `provably_complete:true` with **no proof** → returns `false` (no shard, no proof; fail-closed). |
| 5 | med | `pqanswer` | Nonce compared case-insensitively → **exact match** (opaque nonces are case-sensitive). |
| 9 | med | `omega-bridge` | `hybridCombine` silently ignored a typo'd slot key → **rejects any non-reserved input slot** (no silent weakening). |
| 10 | high | `qiv` | `assertOffchain` accepted `kind:'none'` carrying a dangling `uri`/`sha256` → **rejected** (congruent signed record). |
| 11 | high | `witness-service` | `store.set` not awaited/guarded (silent persistence failure → post-restart equivocation) → **fail-closed** on throw + reject async store in the sync path. |
| 12 | med | `pqauditlog` | `payloadTag` mapped function/symbol/undefined to a shared tag → hash collision → **throws** on unsupported payload type. |
| 13 | high | `pqanchor` | `verifyAnchorChain` didn't enforce a constant log-signer across the chain → **rejects a mid-chain log_signer swap** + optional `trustedLog` pin. |
| 14 | high | `pqcap` | `allowUnmeteredCheck` returned `verified:true` for a `max_uses` token without enforcing the limit → adds **`unmetered:true` + warning** so a non-consuming pre-check can't be mistaken for authorization. |
| 15 | high | `pqdelegate` | Unbounded delegation-chain depth (DoS) → **`maxDepth` guard** (default 64). |
| 17 | high | `pqcbom-report` | Surfaced `pinned:true` even when no key was supplied → surfaced `pinned` is now the **trust** flag (`key supplied AND matched`); internal matches-or-no-key renamed `pinOk`. |

## Rejected on inspection (4) — false positives / cosmetic

| # | Module | Why not a bug |
|---|---|---|
| 6 | `omega-sentinel` | The `seq==null` binding-skip only applies to the synthetic zero-baseline; real postures always carry a numeric ledger seq and are bound via `verifyResponse`. |
| 7 | `omega-gov` | The `seen` Map keys by member_id → each member counted exactly once; an identical duplicate ballot is an idempotent replay (correctly counted once), conflicting ballots already excluded fail-closed. The proposed "flag any 2nd ballot" fix would disenfranchise a voter whose ballot arrives twice. |
| 8 | `omega-chain` | `verifyBatch` already rejects a missing/mismatched commitment fail-closed (`commitment !== canonical`); the ask was a cosmetic error message. |
| 16 | `pqcap.evalCaveats` (misattributed to pqguard) | Already reads **own-properties only** (`Object.hasOwn`) and rejects own getters (`getOwnPropertyDescriptor`); inherited/polluted props resolve to `undefined` and fail positive constraints. Residual is a hypothetical downstream-consumer differential, not an evalCaveats defect. |

All 13 fixes verified by their module self-tests + the full 74-module green-gate. Nothing here changed a wire format or
broke a public API (additive result fields + fail-closed rejections only).

## Round 2 — fix-verification (per the standing discipline: verify every fix for soundness / completeness / regression)

Each of the 13 changed files re-reviewed (7 by an independent agent, 5 by direct code inspection after the agents hit the
StructuredOutput cap — a failed agent return is treated as "did not run", not "clean"). **Result: 12 fixes sound as-is,
1 refinement.** The refinement: **`qiv.verifyInscription` now re-runs `assertOffchain`** at verify time (not only at
`inscribe`), so an incongruent already-signed record (kind='none' + dangling uri/sha256) is rejected on verify regardless
of a valid signature — defense-in-depth completing finding #10. This is a far cleaner fix-verification pass than the
project's historical ~60%-need-refinement rate, attributable to R1's fixes being small fail-closed guards + additive
fields (low complexity) adjudicated in the main loop rather than auto-applied. qiv 21/21, dependents green.

## Coverage-gap closure — posture/admission/monitor cluster (was rate-limited out of R1)

R1's `posture` cluster agent died on a rate-limit and never reviewed 6 modules — a real coverage gap. A dedicated
review→verify pass over them found **3 more confirmed (2 high, 1 med)**, all fixed (adversarial-verify correctly refuted
the pqadmit no-clock and pqmonitor/pqshield null-generated_at candidates — those guards already exist):

| Sev | Module | Defect → fix |
|---|---|---|
| high | `pqcompliance` | `verifyComplianceReport` surfaced `pinned:true` with no key (validity-as-trust) → same resolution as pqcbom-report: surfaced `pinned`=trust, internal `pinOk` keeps the self-consistency mode + `requirePinned` opt. |
| high | `pqgate` | `verifyDecision` `verified:true` for an authentic-but-STALE admission decision replayed under a stricter current policy → added **`current_policy_checked`** (= trustedPolicyId pinned OR recomputed) so an authorization caller can't mistake authenticity for current-policy validity. |
| med | `pqgate` | `evaluateAdmission` let an **omitted** `require_artifact` silently permit unbound admission → now requires an **explicit** `require_artifact === false` opt-out (omitted ⇒ binding required, fail-closed). |

**Run totals (this session): 13 (R1) + 1 (R2 refinement) + 3 (posture) = 17 real security improvements, all fixed +
self-tests green + full 74-module gate green.** Recurring class confirmed again: *validity surfaced as trust* (pqcbom-report
→ pqcompliance) and *authentic ≠ current* (pqgate). No wire-format/API breaks — additive fields + fail-closed guards only.

## Regression-lock — every fix now has a permanent exploit-blocking test

Per the standing lesson (the root cause of recurring bugs was fixes never getting a locked test), each fix got a
dedicated assertion in its module self-test (which runs in the green gate), so a future edit that reopens the hole fails
the gate. **13 modules locked:** pqcbom-report + pqcompliance (`pinned===false` unpinned), pqcap (`unmetered:true`+warning),
pqtransport (`R_trustAnchored` false under TOFU / true when pinned), pqsearch-server (empty-index `provably_complete:false`),
pqx3dh (verify rejects `kem_ot_id:'lastresort'`), pqanswer (case-variant nonce → `nonceOk:false`), pqauditlog (function
payload → throws), qiv (kind:none+dangling uri/sha256 → rejected at inscribe), pqdelegate (`maxDepth` exceeded → rejected),
witness-service (throwing store → cosign fails closed), pqanchor (mid-chain log_signer swap → rejected), pqgate
(`current_policy_checked` false without a pin). (omega-bridge/omega-nexus/pqmesh already shipped their locks with the fix.)
All 13 module self-tests + the full 74-module gate pass.
