# Quantum-Safe Scorecard — deploy runbook (OWNER-GATED)
*Prepared, NOT executed. Every step here requires Brandon's explicit go — Claude will not deploy, publish, register a domain, or set billing autonomously.*

> ## ⏸️ CURRENT POSTURE (owner decision, this session): **PREVIEW-READY, HOLD ALL DEPLOYS UNTIL THE THIRD-PARTY CRYPTO AUDIT.**
> Everything below is staged so it's a one-command launch the day you choose — but **nothing goes live yet.** When it does, it ships as a clearly-labeled **PREVIEW**: every API/worker response and the Evidence Pack already carry `PREVIEW_NOTICE` ("UNAUDITED reference crypto … lexical scanner … not for production reliance until the audit"). Do not strip that label.
>
> **Why this posture:** the CBOM scanner + badge + Evidence Pack are a scanner/report (low blast radius), so a labeled preview is defensible — but they're built on the unaudited `@trelyan/verify-pqc` SDK, which must NOT be presented as production crypto until the external audit clears. The free funnel can soft-launch first; the SDK itself stays draft.

## What's prepared (in this repo, nothing live)
- `worker.mjs` — the hosted `/scan` + `/badge` endpoint handler (uses `pqcbom-server`).
- `wrangler.toml` — Cloudflare Worker config (free tier needs no secrets; paid `full` tier gated by `PAID_KEYS`).
- `../pqcbom-action/` — the GitHub Action (the viral funnel + CI gate).
- Marketing (in the owner's private `program/` — NOT in this public repo): `QUANTUM_SCORECARD_GTM.md` (landing copy + outbound pitch, consolidated) + `QUANTUM_SCORECARD_README.md`.

## Owner steps to go live (when you decide)
1. **Domain (owner):** point `scan.trelyan.dev` at the Worker (DNS + route in `wrangler.toml`). Domain registration/DNS is an owner action.
2. **Deploy the Worker (owner):** `cd deploy && wrangler deploy` (authenticated as the TRELYAN Cloudflare account). Bundle the `pqcbom*` modules (esbuild) or vendor them into the worker.
3. **Paid tier (owner):** `wrangler secret put PAID_KEYS` with the issued enterprise API keys; wire billing (Stripe) out-of-band. For the signed **Evidence Pack** (`/scan {evidencePack:true}`): generate an ML-DSA-87 report-signing keypair offline and `wrangler secret put REPORT_SIGNING_SK` + `REPORT_SIGNING_PK` (hex). Without these, the worker returns the pack **unsigned with a reason** (never silently "signed"). Publish the `REPORT_SIGNING_PK` so buyers can `verifyEvidencePack`.
4. **Publish the GitHub Action (owner):** push `pqcbom-action/` to a public `trelyan/quantum-safe-scorecard` repo, tag `v1`, submit to the GitHub Marketplace (requires accepting the Marketplace agreement — an owner action).
5. **Landing page (owner):** `deploy/landing.html` is the functional front door — set its `API_BASE` const to your deployed worker URL (e.g. `https://scan.trelyan.dev`), then publish it to the site (Netlify deploy is owner-gated per the website-deploy rule). It carries the PREVIEW banner + honest limitations, embeds the live shields badge, and has working `/scan` + `/verify` forms (CORS is `*` on the worker). It is HTML/CSS only — no mock imagery (media policy). Also place a real `/.well-known/security.txt` (footer links it).
6. **Outbound (owner):** the pitch (owner's private `program/QUANTUM_SCORECARD_GTM.md`) is a DRAFT — sending it to real prospects is an owner action (no autonomous sending).

## Go-live preflight checklist (tick before the preview soft-launch)
- [ ] Audit posture confirmed: funnel ships as **PREVIEW**; the crypto SDK is NOT presented as production. `PREVIEW_NOTICE` present on all responses.
- [ ] `wrangler whoami` = the TRELYAN Cloudflare account; `wrangler deploy` from `deploy/`.
- [ ] `PAID_KEYS` set; (optional) `REPORT_SIGNING_SK`/`PK` set + public key published for Evidence-Pack verification.
- [ ] Landing copy carries the preview/limitations banner; lexical-scanner caveats visible.
- [ ] Rate-limit / abuse protection on `/scan` (Worker rate limiting or Cloudflare WAF).
- [ ] GDPR: `/scan` is stateless by default; if you persist results, add a retention + DPIA note (and never log file contents).
- [ ] GitHub Action repo public + `v1` tag; Marketplace listing reviewed.

## Hard boundary
Claude prepares configs, code, and copy. **Deploying, publishing, registering domains, setting billing/secrets, and sending outreach are all owner-only.** Current standing instruction: **hold all deploys until the third-party crypto audit** (preview soft-launch of the funnel is the first thing to unblock, on Brandon's explicit go).
