# Audit Engagement Kit — owner action package (TRELYAN PQ SDK)

> **⚠️ BUDGET REALITY (council-revised):** a full crypto + side-channel audit is **$15k–50k+** — it does **not** fit a
> ~$2k budget. Do **not** cold-buy it. The realistic path is a **funded** audit: **OSTIF** or **NLnet** (brokers/funders
> that pair OSS projects with firms like Trail of Bits at a funder's expense), or a **federal grant with the audit as a
> funded task** (your NRL/SBIR white papers). See **`AUDIT_OUTREACH.md`** for the funded-first outreach sequence. The
> firm-selection matrix below still applies — but as "who the funder pairs you with," not "who you pay out of pocket."

The full 11-seat council was **unanimous**: commissioning an independent crypto + side-channel audit is the single
highest-value next move — it is the gate that turns the reference SDK into something deployable, sellable, and
federal-credible (a third-party code+SCA audit is the recognized INTERIM assurance signal ahead of the heavier
FIPS 140-3 CMVP; CAVP/ACVP algorithm validation is the nearer-term federal checkbox). This kit makes commissioning a
**single owner decision**: pick a firm, send the email, sign the SOW.

> **Boundary (unchanged):** Claude prepared this kit. Claude does **not** contact firms, negotiate, sign, or pay —
> those are owner actions. Cost/lead-time figures below are *typical industry ranges to confirm in a scoping call*,
> not quotes. Nothing here represents any module as production-ready until an audit closes and lifts the caveat.

## What an auditor receives (already turnkey, offline-reproducible)
`AUDIT_RFP.md` (scope/SOW) + the materials in its §4 — incl. the two new meta-harnesses (`tamper-binding.mjs`,
`domain-separation.mjs`) and `SECURITY_REVIEW.md` logging the **5 real gaps the harnesses already caught and we fixed**
(pqindex shard `ts`; pqx3dh one-time PQ prekeys / Signal-PQXDH HNDL; pqcompliance `summary`/`disclaimer`/`posture`
caveat-stripping; pqpki Ed25519 context-binding; + the totality/fail-closed sweep). This materially narrows the
engagement: functional correctness, fail-closed behaviour, signature-coverage, and domain-separation are already
demonstrated by runnable harnesses, so the firm's highest-value focus is **side-channel / constant-time** + an
independent confirmation pass.

## Firm shortlist (PQC-capable; owner selects — not an endorsement)

| Firm | Why for us | JS/TS crypto | Side-channel/CT | Notes |
|---|---|---|---|---|
| **Trail of Bits** | Deep applied-crypto practice; **leading on constant-time tooling** (shipped LLVM constant-time support, 2025); has audited JS crypto libraries and disclosed real bugs in them. | Yes (audits JS crypto) | Strong (CT tooling) | **Primary recommendation** for a JS/TS SDK that needs both code review AND a credible SCA opinion. US-based (federal-friendly). |
| **NCC Group — Cryptography Services** | Established crypto-audit house with explicit **PQC/ML-DSA** expertise; well-known public PQC reports. | Yes | Strong | **Co-primary.** Brand recognized by enterprise/federal buyers — the report itself carries procurement weight. |
| **Kudelski Security** | PQC practice oriented to **certification/compliance navigation** (CNSA 2.0 / FIPS path). | Partial | Yes | Good if the priority is the FIPS/CNSA roadmap alongside the audit. |
| **SandboxAQ** | PQC software + **formal-verification** depth (EasyCrypt KEM proofs); large PQC org. | Partial | Some | Best if you want formal-methods rigor on the primitives' usage. |
| **Quarkslab** | PQC + **side-channel/fault-injection** lab; European (Airbus-owned) → **EU-sovereignty / eIDAS2 angle**. | Partial | Strong (HW SCA) | Pick for the EU/Swiss regulatory framing (NIS2/CRA/eIDAS2). |
| **Cure53** | **JS/TS-native** audit shop (OpenPGP.js, many VPN/crypto web audits); fast, focused. | Strong | Limited | Best-fit for the JavaScript implementation review specifically; pair with a SCA-strong firm if constant-time is in scope. |
| **PQShield** | PQC specialists (standards contributors). | Partial | Yes | Strong primitive expertise; more HW/IP-oriented. |

**Recommendation:** lead with **Trail of Bits or NCC Group** (both cover JS code-review *and* side-channel — our two
needs in one engagement). If budget is tight and side-channel is deferred to a later phase, **Cure53** is the
cost-effective JS-implementation review. If the EU regulatory story is the priority, **Quarkslab**.

## Typical engagement shape (confirm in scoping — NOT a quote)
- For a ~10k-LOC JS/TS crypto SDK: a focused code review + crypto-correctness pass is commonly a **2–4 week**
  engagement; adding a **constant-time / side-channel** assessment extends scope/fee. Lead time to *start* is often
  **several weeks to a quarter** (book early). Fees scale with scope/firm tier — get **2–3 written scoping bids**.
- Phasing option to control cost: **Phase 1** = spine + domain-separation + signature-coverage confirmation +
  canonicalization (cheaper, unblocks the "audited core" claim for the revenue products); **Phase 2** = full
  side-channel/constant-time across the primitives' usage.

> **Ready-to-send, per-firm versions** of the email below (tailored to Trail of Bits / NCC Group / Cure53) are in
> **`AUDIT_OUTREACH.md`** — copy-paste-send from your own email.

## Cover-email template (owner sends; fill the brackets)
> Subject: PQC SDK security audit — scoping request (~10k-LOC JS/TS, @noble/post-quantum)
>
> Hi [name],
>
> We're TRELYAN [TRELYAN Inc., Delaware]. We've built a post-quantum verification SDK (ML-KEM-1024 / ML-DSA-87 /
> SLH-DSA / Falcon-1024-on-chain) in JavaScript on the audited `@noble/post-quantum` primitives, and we're seeking an
> independent crypto code review + side-channel/constant-time assessment before production use.
>
> The codebase is ~10k LOC across ~28 modules built on a single RFC-6962 transparency spine. It ships with a turnkey
> audit package: formal spec, threat + adversary models, reproducibility/SBOM, a 42k-case differential validator, a
> fuzz/fail-closed sweep, a signature-coverage (tamper-binding) harness, and a domain-separation harness — plus a full
> review log of issues we've already found and fixed. We'd like the engagement to confirm our harnesses and focus on
> the side-channel surface (the reference is explicitly not constant-time).
>
> Could we set up a 30-min scoping call? I can share the audit package under NDA. Targeting a start in [month].
>
> Thanks, [name / title / TRELYAN]

## Owner readiness checklist (before the scoping call)
- [ ] Decide scope: full (code + side-channel) vs phased (Phase 1 first).
- [ ] Confirm budget band + target start month.
- [ ] Choose 2–3 firms from the shortlist; send the cover email for written bids.
- [ ] Have the audit package ready to share under NDA (it's in this repo: `AUDIT_RFP.md` + §4 materials).
- [ ] Decide which modules MUST shed the "unaudited" caveat first (recommend: the spine + the revenue products —
      pqcbom-report Evidence Pack + pqcompliance — since those are what sells).
- [ ] (Optional) ask each firm whether they also help navigate **CAVP/ACVP** algorithm validation as a federal
      checkbox alongside the code audit.

> Standing reminder: until an audit closes and the caveat is lifted **per module**, no module is to be represented as
> production-ready or standards-conformant. This kit enables the decision; it does not change that posture.
