# Audit Outreach — funded-audit path (council-revised; OWNER sends)

**Reality (be honest with yourself and them):** a full crypto + side-channel audit from a top firm is **$15k–50k+** (Moonshot warns $40–100k with real timing analysis). With a ~$2k budget you do **not** buy this — you get it **funded**. So the order below is: **(A) funding brokers first** (OSTIF / NLnet — they pair OSS projects with firms at third-party expense), **(B) a federal grant with the audit as a funded task** (your NRL/SBIR white papers), and only **(C) cold firm contact** framed as grant-backed/scoped.

> **Boundary:** Claude drafted these. Claude does not send email, sign, or pay — you send, from your own address.
> **Council note (8 seats, unanimous): do NOT send the old versions.** These are rewritten to fix: hidden budget,
> "turnkey"/checklist overclaim, the naive "constant-time in JS" ask, NDA-as-precondition, and inflated metrics.
>
> **Fill before sending:** `[your name/email]` · `[public repo URL + commit/tag]` · `[runtime: Node 18+ and/or browser]`.
> **Accurate facts to use (verified):** ~**5,500 LOC of custom SDK code** (on top of the *separately-audited*
> `@noble/post-quantum` primitives — don't claim that audit as your own); the differential validator checks our
> RFC-6962 transparency code against an **independent re-implementation** (not NIST vectors); NIST-style KAT vectors
> live in `kat-conformance.mjs`. The SDK is **unaudited, research-grade, not constant-time, not FIPS-validated.**

---

## A1 — OSTIF (Open Source Technology Improvement Fund) — *the highest-probability path*
**Why first:** OSTIF brokers and funds third-party audits for open-source projects, pairing them with firms like Trail
of Bits at a funder's expense (recent: the LibVLC audit, executed by Trail of Bits, funded by the Sovereign Tech
Agency). This converts "we can't afford an audit" into "help us get one funded." **Intake:** via ostif.org (confirm
current contact form).

> Subject: Funded-audit interest — open-source post-quantum verification library (JS)
>
> Hi OSTIF team,
>
> I maintain an MIT-licensed, open-source post-quantum **verification** library in JavaScript — it wraps the
> independently-audited `@noble/post-quantum` primitives (ML-KEM-1024, ML-DSA-87, SLH-DSA) to provide signed
> transparency/provenance (an RFC-6962 Merkle log), hybrid certificates, and a CBOM/migration-evidence tool. The custom
> code is ~5,500 LOC; it is research-grade and **unaudited**, and I'd like to get it independently reviewed before
> recommending production use.
>
> Is this a fit for an OSTIF-brokered, funder-backed audit? I have a reviewer package ready (formal spec,
> threat model, reproducibility/SBOM, a differential validator against an independent RFC-6962 re-implementation, and
> negative-test harnesses). Repo: [public URL]. I'd welcome guidance on whether to pursue this via OSTIF and how to
> apply. Thank you — [name].

## A2 — NLnet / NGI Zero — *funded OSS audit, esp. the Cure53 route*
**Why:** NLnet's NGI Zero funds open-source security/privacy work and routinely funds independent audits (often executed
by Cure53). ⚠️ **Confirm eligibility for a US for-profit** — NGI is EU-funded; you may need to apply as the individual
maintainer of the open-source project, or check the current call's rules. **Intake:** nlnet.nl submission form (calls
run on a recurring cadence — check the open call + deadline).

> Subject: NGI Zero — funding an independent audit of an open-source PQC verification library
>
> Hi NLnet team,
>
> I maintain an MIT-licensed open-source post-quantum verification library (JavaScript, on `@noble/post-quantum`):
> signed RFC-6962 transparency, hybrid certs, and crypto-discovery/migration evidence (~5,500 LOC of custom code,
> unaudited). I'd like to apply for support to fund an independent security audit (and to harden the library based on
> it). Could you advise whether this fits an open NGI Zero call and the eligibility for an individual maintainer / a
> small US company? Repo + reviewer package available. Thank you — [name].

---

## C — Cold firm contact (only as grant-backed/scoped; send AFTER or alongside A)
Each rewritten to be budget-honest, claim-accurate, and humble. A 30-min scoping call is free; **don't commit to a paid
SOW you can't fund.** Consider also one mid-tier firm (the three below are high-end and may decline at this budget).

### Trail of Bits — *contact via the form at trailofbits.com/contact*
> Subject: Scoping a (likely grant-funded) review of an open-source PQC JS library
>
> Hi Trail of Bits team,
>
> I maintain an MIT-licensed, open-source post-quantum **verification** library in JavaScript (Node + browser), built on
> the independently-audited `@noble/post-quantum` primitives (ML-KEM-1024, ML-DSA-87, SLH-DSA). The audit target is
> ~5,500 LOC of custom code: an RFC-6962 transparency log, hybrid certificates, and a CBOM/migration-evidence tool.
> Repo: [public URL], tag [commit]. It is **unaudited and not constant-time**.
>
> I'm scoping a focused review and want to be upfront on funding: I have a small scoping budget (~$2k) and am pursuing
> grant funding (OSTIF / NLnet / a US federal SBIR audit-task) to cover the engagement — so I'm looking to understand
> feasibility, likely scope, and a rough order-of-magnitude cost I can write into a grant application. The review I have
> in mind: (1) correctness/spec-conformance of the custom code and key-handling; (2) a **review of secret-independent
> source patterns and known JS timing-leak classes**, with the explicit understanding that the JS runtime cannot be
> made constant-time (so this is a source-level + design review, not a hardware side-channel pass).
>
> Would a scoped or grant-backed engagement fit your model? I can share the spec and threat model openly, and the full
> source under your standard MNDA. Happy to find a time that works for you. — [name]

### NCC Group — *Cryptography Services* (reach via the technical-assurance contact; put "Cryptography Services" in the subject)
> Subject: Cryptography Services — scoping a grant-funded review of an open-source PQC JS library
>
> Hi NCC Group Cryptography Services,
>
> [Same body as above, adjusted:] …your published PQC / ML-DSA work is why I'm reaching out. I'd value your read on the
> custom code (~5,500 LOC), the domain-separation and signature-coverage design, and the realistic limits of timing
> analysis in a JS runtime. Funding: small scoping budget + pursuing grant funding — seeking feasibility + a
> rough-order cost to put in a grant application. Spec/threat-model shareable openly; full source under your MNDA. — [name]

### Cure53 — *confirm the current intake address before sending*
> Subject: Source-review scoping — open-source PQC verification library (JS), grant-funded
>
> Hi Cure53,
>
> I maintain an MIT-licensed JS/TS open-source PQC verification library (on `@noble/post-quantum`); ~5,500 LOC of custom
> code — your JS/TS audit work (e.g. OpenPGP.js) is the fit. I'm pursuing **NLnet/NGI funding** for an independent audit
> and would value your input on scope, given your experience with NGI-funded open-source audits. Could we discuss a
> focused source review (and whether a separate timing-analysis pass is warranted)? Spec shareable openly; source under
> your MNDA. — [name]

---

## What changed + why (for your records)
- **Added the funded-audit brokers (OSTIF, NLnet) as the lead path** — the realistic way to get a real audit at this budget.
- **Disclosed the budget + grant intent in every firm email** — the council's #1 fix; prevents a wasted call + reads as honest, not desperate.
- **Cut "turnkey package" and the harness checklist** → plain, factual description + repo link.
- **Reframed the side-channel ask honestly** — JS cannot be constant-time; ask for a source-level/design review, not a hardware SCA pass on code known to leak.
- **Corrected the metrics** — ~5,500 LOC custom (not "10k / 28 modules"); differential is vs an *independent re-implementation* (named the oracle); didn't claim @noble's audit as our own.
- **Removed NDA-as-precondition** — spec/threat-model open, full source under the firm's standard MNDA.
- **Labeled Falcon as the experimental/on-chain leg** (out of the cold-email opener).
