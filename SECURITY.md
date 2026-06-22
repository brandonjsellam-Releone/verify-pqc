# Security Policy

`@trelyan/verify-pqc` is a **TestNet, unaudited** post-quantum verification toolkit. The thing we
care about most is **soundness** — anything that makes the tool show a false **"verified"** /
**"cross-anchor verified"** verdict. We treat those as the highest-severity bugs.

## Reporting a vulnerability

Please report privately — **do not** open a public issue for a security bug:
- open a **GitHub private security advisory** on this repo (Security → Advisories → Report a vulnerability), **or**
- email **security@trelyan.foundation** *(ensure this routes to a monitored inbox, or replace with your address)*.

Include: what you found, the file/line, a reproduction, and the impact — especially **any path to a
false-positive verification** (a green verdict an attacker can earn without breaking the intended keys).

We aim to **acknowledge within 3 business days** and to agree a disclosure timeline with you. Please
allow reasonable time to fix before public disclosure (we suggest **90 days**).

## Scope

**In scope:** verifier soundness (false `verified` / `cross-anchor verified`), the `@trelyan/verify-pqc`
SDK, the in-browser verifiers (`verify-live`, `verify-unified`, `anchor`, `pqbadge`), the Netlify proxy
(`site-integration/`), and the conformance tooling.

**Out of scope (documented limitations, not bugs):** the TestNet/unaudited status itself; third-party
indexers' availability; single-indexer trust (disclosed in-page); the Layer-1 ML-DSA STH signature not
being re-verified in-browser (see `anchor/THREAT_MODEL.md`).

## Recognition

We're glad to credit reporters (with permission). There is no paid bug-bounty at this time.
