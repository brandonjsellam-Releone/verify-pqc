# AGENTS.md — TRELYAN `verify-pqc` SDK · rules for AI dev tools (Cursor, Windsurf, Claude Code, StarCoder2)

This is a **dependency-light post-quantum REFERENCE implementation**. The rules below are HARD — code that
violates them must not be committed. Cursor and Windsurf read this file (plus `.cursorrules` / `.windsurfrules`);
follow it exactly.

## Non-negotiables
1. **Dependency-light.** Crypto ONLY via `@noble/post-quantum` + `@noble/curves` + `@noble/hashes`. No new runtime
   dependency without explicit owner sign-off.
2. **0-downgrade, only-upgrade.** Every change is additive; nothing that passes may regress.
   `PQC_SKIP_LIVE=1 node test-all.mjs` MUST print **`ALL MODULES PASS`** before any commit. Modules may be ADDED,
   never silently removed — the `MIN_MODULES` ratchet in `test-all.mjs` enforces this (raise it when you add one).
3. **Canonical JSON.** Every module's `canon()` must be byte-identical to the SDK reference (sorted-key,
   type-distinct) — `canon-determinism.mjs` checks the exact fragments. Copy verbatim:
   ```js
   function canon(v){ if(v===null||typeof v==='number'||typeof v==='boolean'||typeof v==='string')return JSON.stringify(v);
     if(Array.isArray(v))return '['+v.map(canon).join(',')+']';
     return '{'+Object.keys(v).sort().map((k)=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}'; }
   ```
4. **TOTAL / fail-closed verifiers.** Every `verify*()` wraps in try/catch and returns `{verified:false}` on ANY
   malformed input — it NEVER throws. (`fuzz-robustness.mjs` proves this.)
5. **Hybrid AND-composition.** When signing with more than one scheme (Ed25519 ∧ ML-DSA-87 ∧ SLH-DSA), ALL legs
   must verify — stripping any leg must FAIL (anti-downgrade).
6. **Domain separation.** Every signed/hashed context string is UNIQUE to one module (`trelyan-<module>-v1`).
   (`domain-separation.mjs` checks uniqueness.)
7. **Self-test + wire-in.** Every module ends with a self-test that prints `"<module> self-test: N pass, 0 fail"`
   and is added to `test-all.mjs`'s `mods` array.

## Honesty discipline (claims must be falsifiable)
- NEVER write "military-grade", "unbreakable", "FIPS-validated/certified", "quantum-proof", "guaranteed 0-downgrade".
- DO say: "downgrade-detecting under the declared trust model", "tamper-EVIDENT (not tamper-proof)",
  "unaudited reference implementation".
- `liboqs` is NOT "NIST-certified"; FN-DSA / FIPS-206 is NOT finalized; NERION is software + cloud-KMS, NOT "HSM-backed";
  the canonical QLR ledger is **Algorand** (Falcon-1024 / `falcon_verify`), with QRL/Zond an optional second PQ chain.

## Secrets
- No secrets in code, tests, logs, or committed files. `.env` stays OUT of git. Before committing, confirm no
  `.env` / `_scratch*` / key material is staged.

## StarCoder2 (the code-gen helper in this stack)
- StarCoder2 is a CODE model — use it for completion / fill-in-the-middle, NOT for architecture or security reasoning.
- Client: `python -m apex_jarvis.tools.starcoder2 "def foo():"` or
  `python -m apex_jarvis.tools.starcoder2 --infill --prefix "..." --suffix "..."` (reads `HUGGINGFACE_API_KEY` from `.env`).

## Before every commit
1. `PQC_SKIP_LIVE=1 node test-all.mjs` → `ALL MODULES PASS`.
2. No secrets / scratch files staged.
3. Every new claim is falsifiable (none of the banned words above).
