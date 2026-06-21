# Post-quantum suite — what's built & how to ship it

Everything here is **built, tested, and staged**. Deploys are **owner actions** (outward-facing /
irreversible) — none were executed autonomously. App `763809096`, its ABI, and box prefixes were
never modified; the chain was only read.

## Inventory (all validated)

| Artifact | Path | Status |
|---|---|---|
| Live on-chain verifier | `web/verify-live.html` | ✅ runs live against 763809096 |
| Unified verifier (on-chain + THRONDAR) | `web/verify-unified.html` | ✅ |
| pqBadge drop-in + demo | `web/pqbadge.js`, `web/pqbadge-demo.html` | ✅ |
| Two-layer anchor log | `web/anchor.html` | ✅ commitment == anchor_sth.py |
| Post-quantum trust hub | `web/index.html` | ✅ |
| `verify.html` live section | `web/verify-section.snippet.html` | ✅ paste-ready |
| JS SDK | `packages/verify-pqc/` | ✅ 8/8 (unit + live) |
| Anchor tool | `anchor/anchor_sth.py` | ✅ prepare + verify |
| Conformance spec | `SPEC.md` | ✅ ground-truth-correct |
| Conformance core + KATs | `falcon_interop.py`, `onchain_probe.py`, `kat/` | ✅ FN-DSA over-claim removed |
| License | `LICENSE` (MIT) | ✅ |

## Owner steps to go live (each gated — run when you choose)

1. **Publish the kit (GitHub).** ✅ **DONE** — live (public) at
   <https://github.com/brandonjsellam-Releone/verify-pqc>. The conformance CI runs on push.
   *(Rename/transfer to a `trelyan` org later if desired, then update the link in `web/index.html`.)*

2. **Publish the SDK (npm).** A CI workflow is wired: `.github/workflows/npm-publish.yml`
   publishes `@trelyan/verify-pqc` on a GitHub Release using a `NPM_TOKEN` secret. You do once:
   create the free `trelyan` org on npmjs.com, add `NPM_TOKEN` (repo → Settings → Secrets),
   then cut a Release (or run the workflow). `@trelyan/verify-pqc` is unclaimed today. *(npm
   account/scope = yours; the trigger stays with you since publish is irreversible.)*

3a. **Web tools — ALREADY LIVE on GitHub Pages:** <https://brandonjsellam-releone.github.io/verify-pqc/>
    (hub + verify-live/unified/anchor/pqbadge). CNAME `pq.trelyan.foundation` → Pages to put it on-domain.

3b. **Web tools on trelyan.foundation (CSP-safe drop-in).** Use `site-integration/` — it makes
    the verifiers work under the site's strict CSP via a same-origin proxy (no CSP change). From
    the **full** site checkout: copy `site-integration/netlify/functions/pqproxy.mjs` +
    `site-integration/pq/` in, then `cd website/v2 && netlify deploy --prod`. See
    `site-integration/NETLIFY_ADDITIONS.md`. *(Don't deploy from the partial OneDrive copy — it's
    missing the cloud-only functions; deploying it would wipe the live `/api/*` routes.)*

3c. **Transfer the repo to a `trelyan` GitHub org (optional).** The org doesn't exist yet — create
    it on github.com (yours), then: `gh api repos/brandonjsellam-Releone/verify-pqc/transfer -f new_owner=trelyan`,
    and update the link in `web/index.html` + `docs/index.html`.

4. **Enhance verify.html.** Paste `web/verify-section.snippet.html` into `website/v2/verify.html`
   after the "§ I On-chain" section, then redeploy.

5. **Cut the first anchor (two-layer).** `python anchor/anchor_sth.py prepare --out anchor-1.json`
   → Falcon-sign the `commitment_sha512_256` with the trelyan-pq key and `inscribe` it on a
   **sandbox app** (or 763809096 if you intend to consume a real cell) → add `{txid, sth}` to
   `web/anchors.json` so `anchor.html` lists + verifies it. *(Signing + spending = owner only.)*

6. **The algo-pqc-kit interop reply** (from earlier) stays a **draft** to post yourself; the
   conformance suite + golden KAT back it up.

## Hard constraints honored
- Deployed app `763809096` / ABI / box-prefixes untouched (read-only).
- GitHub publish + Pages done (authorized, reversible). NOT done — yours by rule: npm publish,
  the anchor sign+inscribe, any Netlify/Vercel/bridge deploy. No keys read; no funds spent; no CSP/security setting changed.
- Honest framing throughout: TestNet · unaudited; `0xBA` = trelyan-pq wrapper, not a NIST/FIPS field;
  Falcon = signatures, not encryption; "reference + conformance suite", not "the standard".
