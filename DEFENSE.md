# Defensive posture — verify-pqc

**No system is unhackable, and this one is TestNet + unaudited.** What follows is *defense-in-depth* —
layered, honest controls so a single failure doesn't become a compromise — plus a transparent way to
respond when something gets through. Any claim of an "unbreakable" shield would be the dishonesty this
project exists to avoid: the whole point is *verifiable* trust, not asserted trust.

## The threat that matters most: a false "verified"
For a verification tool, the worst attack isn't downtime — it's making the tool **lie** (show a green
verdict for something an attacker controls). Defenses, in order of importance:

1. **Soundness gating (the core).** A green verdict is bound to facts an attacker *cannot* forge, not to
   shape heuristics:
   - On-chain verdicts are gated on **recognized, chain-assigned app-ids** (`763809096`, `764917520`) —
     app-ids are unforgeable, so an attacker can't present their own app as TRELYAN's.
   - The anchor verdict is bound to a **real `inscribe()` call** (method selector + commit arg position),
     not "any 32-byte arg on any txn."
   - **Layer-1 ML-DSA-87** verification pins THRONDAR's published key `0986d89fa3c74566` and checks the
     digest chain — a substituted key+signature is rejected.
   - A **regression test** (`packages/verify-pqc/test.js`) asserts a sig+box on an unrecognized app does
     **not** verify, so the fix can't silently regress.
   - These came from an **adversarial review that found and fixed 4 real false-verify paths** — see the git history.

2. **Supply-chain integrity.**
   - The vendored `js-sha512` and the jsdelivr `<script>` carry **Subresource Integrity** (`sha384-…`) +
     `crossorigin` — a tampered CDN file is rejected by the browser.
   - **Dependabot** (`.github/dependabot.yml`) watches npm + GitHub-Actions deps.
   - The SDK core is **dependency-free**; the only added crypto (`@noble/post-quantum`, audited) is an
     *optional* module, version-pinned.
   - ⚠️ **Honest caveat:** the in-browser ML-DSA page loads `@noble` from `esm.sh` (a dynamic CDN). For a
     production deployment, **vendor `@noble` locally** (or self-host) so the verifier's own crypto can't
     be swapped by a CDN compromise. The npm module (`@trelyan/verify-pqc/mldsa`) is the vendored path.

3. **Injection / XSS.** All rendered on-chain/API values pass through `esc()`; the CSP-safe drop-in
   (`site-integration/`) keeps trelyan.foundation's strict `script-src 'self'` / `connect-src 'self'`
   **intact** via a same-origin proxy — no inline scripts, no cross-origin fetch from the page.

4. **Transport + headers.** HTTPS everywhere; the foundation site ships HSTS + a strict CSP +
   `X-Content-Type-Options` + `frame-ancestors 'none'`.

## Residual risks we do NOT pretend away
- **TestNet, unaudited** — no external security/crypto audit yet (the standing #1 action).
- **Single-indexer trust** — verifiers reflect one indexer's view; cross-check ≥2 / self-host for assurance.
- **esm.sh CDN** for the ML-DSA page (above) — vendor before production.
- **Layer-1 for historical anchors** — the existing anchor predates receipt-capture, so its Layer-1 STH
  signature isn't re-verifiable from stored data; future anchors capture the receipt.

## When something gets through
Report it privately (`SECURITY.md`); we acknowledge in ≤3 business days. Operationally, detection +
the 24h/72h response flow live in the [NIS2 IR runbook](../compliance/NIS2_Incident_Response_Runbook.md)
(local). The honest posture is **layered defense + fast, transparent response** — not invincibility.
