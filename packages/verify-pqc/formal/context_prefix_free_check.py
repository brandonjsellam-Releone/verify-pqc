#!/usr/bin/env python3
"""
CODE-LEVEL companion to domain_separation_z3.py: verify the DEPLOYED context registry is PREFIX-FREE.
================================================================================================
domain_separation_z3.py proves domain separation GIVEN an injective (ctx, m) -> bytes encoding.
For the ML-DSA/SLH-DSA legs the FIPS-204/205 context parameter is length-prefixed inside the
algorithm, so injectivity holds structurally. For Ed25519 legs the SDK signs ctx || m by RAW
CONCATENATION (pqseal.mjs: `ed25519.sign(concatBytes(c, m), sk)`) — there, injectivity across
contexts holds IFF no deployed context string is a proper prefix of another:

    ctxB = ctxA || s   ⇒   ctxA || (s || m') == ctxB || m'   (a cross-context collision, 0 forgeries)

This script extracts EVERY context constant in the SDK (utf8ToBytes('...') assigned to *CTX* /
passed as a context) and asserts pairwise prefix-freeness. Run in CI next to run_all.py.

Exit 0 = registry is prefix-free (the Z3 proof's injectivity assumption is discharged for the
concatenation path). Exit 1 = a REAL cross-context-collision hazard — fix the context strings.
"""
from __future__ import annotations
import os
import re
import sys

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # packages/verify-pqc

# every string literal handed to utf8ToBytes(...) that is used as a signing context. Contexts in
# this SDK are versioned kebab constants (e.g. 'trelyan-pqseal-v1'); we collect ALL utf8ToBytes
# literals that look like context tags (conservative: any literal containing '-v' + digits or 'ctx').
LIT = re.compile(r"utf8ToBytes\(\s*'([^']+)'\s*\)")
CTXISH = re.compile(r"(-v\d+|ctx|context)", re.IGNORECASE)


def collect():
    found = {}  # ctx string -> [locations]
    for root, _dirs, files in os.walk(PKG):
        if any(part in root for part in (os.sep + "node_modules", os.sep + ".git", os.sep + "dist")):
            continue
        for fn in files:
            if not fn.endswith((".mjs", ".js")):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for mth in LIT.finditer(text):
                lit = mth.group(1)
                if CTXISH.search(lit):
                    found.setdefault(lit, []).append(os.path.relpath(path, PKG))
    return found


def main() -> int:
    reg = collect()
    ctxs = sorted(reg)
    if not ctxs:
        print("context_prefix_free_check: FAIL — no context constants found (extractor broken?)")
        return 1
    violations = []
    for i, a in enumerate(ctxs):
        for b in ctxs[i + 1:]:
            if b.startswith(a) and a != b:          # sorted ⇒ only b can extend a
                violations.append((a, b))
    print(f"context registry: {len(ctxs)} distinct context strings extracted across the SDK")
    if violations:
        for a, b in violations:
            print(f"  VIOLATION: '{a}' is a proper prefix of '{b}'")
            print(f"             '{a}' in: {', '.join(sorted(set(reg[a]))[:4])}")
            print(f"             '{b}' in: {', '.join(sorted(set(reg[b]))[:4])}")
        print("")
        print(f"context_prefix_free_check: FAIL ({len(violations)} prefix collision hazard(s)) — "
              "raw ctx||m concatenation is NOT injective across these contexts.")
        return 1
    print("  ok   pairwise prefix-free — raw ctx||m concatenation is injective across the registry")
    print("")
    print("context_prefix_free_check: PASS — the Z3 injectivity assumption is discharged for the "
          "concatenation (Ed25519) path.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
