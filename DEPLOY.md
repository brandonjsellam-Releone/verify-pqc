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

2. **Publish the SDK (npm).** `cd packages/verify-pqc && npm publish --access public`
   (requires an npm account + the `@trelyan` scope; this is a financial/account action — yours).

3. **Ship the web tools to trelyan.foundation.** Copy `web/*.html` + `web/pqbadge.js` into
   `website/v2/`, add nav links (e.g. a "Verify live" entry → `verify-live.html`, "Anchor" →
   `anchor.html`), then `cd website/v2 && netlify deploy --prod`. *(Deploy is owner-gated per
   project policy — never autonomous.)*

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
- No Netlify/Vercel/bridge deploys executed; no GitHub posts; no npm publish; no keys read.
- Honest framing throughout: TestNet · unaudited; `0xBA` = trelyan-pq wrapper, not a NIST/FIPS field;
  Falcon = signatures, not encryption; "reference + conformance suite", not "the standard".
