# Canonicalization Specification — `canon()` (audit input)

The byte-determinism root of every signature in the SDK. A signed core is always `utf8ToBytes(canon(core))`, signed
with ML-DSA-87 under a domain-separation context. This document specifies `canon()` exactly so an independent
implementation can reproduce the signed bytes and an auditor can reason about collision resistance.

> Reference: `pqsign.mjs` (the spine). Proven consistent across all 10 signing modules + property-tested by
> `canon-determinism.mjs` (16 assertions). Conformance to RFC 8785 (JCS) is **approximate**, not claimed — see §5.

## 1. Definition (normative)
```
canon(v):
  if v is null OR number OR boolean OR string:  return JSON.stringify(v)
  if v is Array:                                return "[" + join(",", map(canon, v)) + "]"
  otherwise (object):                           return "{" + join(",", map(k => JSON.stringify(k) + ":" + canon(v[k]),
                                                                          sort(Object.keys(v)))) + "}"
```
- **Object keys are sorted** (`Array.prototype.sort`, default lexicographic on UTF-16 code units) → author key order is
  irrelevant to the signed bytes (signer and verifier agree regardless of insertion order).
- **Keys and string values are `JSON.stringify`-escaped** → `"`, `:`, `,`, `{`, `}`, control chars, and non-ASCII are
  escaped inside quotes; they cannot be smuggled to forge a key/value boundary.
- **Arrays preserve element order** (order is semantically significant, unlike object keys).
- Output is a compact JSON string with **no insignificant whitespace**.

## 2. Value-domain contract (in-scope inputs)
`canon()` is defined for **plain JSON values** only: `string | number | boolean | null | array | object` whose nested
values are themselves plain JSON values. Signed cores are constructed from JSON-derived data and contain only:
hex strings, ASCII identifiers, **integers** (counts, tree sizes, unix-second timestamps), booleans, `null`, and arrays/
objects thereof.

**Out-of-contract values** (never present in a signed core): floating-point/non-integer numbers, `BigInt`, `NaN`,
`±Infinity`, `-0`, `undefined`, `Symbol` keys, functions, `Date`, typed arrays, Maps/Sets, `Proxy`, objects with a
`toJSON`/`valueOf`/`Symbol.toPrimitive` hook. These are **not** silently mis-serialized into a valid signature:
- In the current implementation, `canon()` is a manual recursive walk — it does not pass a rich object to
  `JSON.stringify` on the covered signing paths, so `toJSON` / `Symbol.toPrimitive` hooks are not invoked and
  `Object.keys` ignores `Symbol` keys (0 fail-open **observed** on those inputs across the `fuzz-robustness.mjs` corpus;
  a source-level invariant, not a formal proof).
- An out-of-contract value reaching `canon()` either throws (BigInt → `JSON.stringify` throws; `undefined`/function →
  object branch `Object.keys` path) or serializes deterministically; the verifiers wrap canon+verify in try/catch and
  fail CLOSED (no throw **observed** across the 58 adversarial input classes in `fuzz-robustness.mjs`).

## 3. Collision resistance over the in-scope value domain (test-evidenced, not a formal proof)
For the value shapes used in signed cores, distinct values map to distinct strings. `canon-determinism.mjs` *checks*
this over the tested cases below (it is evidence, not a formal injectivity proof over the whole input space):
- **Type-distinct:** `"1"≠1`, `true≠"true"`, `null≠"null"/0/false`, `0≠false` — JSON literal forms differ.
- **Structure-distinct:** array `[1]` ≠ object `{"0":1}` (the `[` vs `{` prefix); `{}`≠`[]`≠`""`; nesting is significant
  (`{"a":{"b":1}}` ≠ `{"a":1,"b":1}`); quote-delimited boundaries prevent concatenation collisions
  (`{"a":1,"b":2}` ≠ `{"a":12}`).
- **Key-escaped:** delimiter/whitespace/unicode in a key is escaped (`{"a:b":1}` ≠ `{"a":{"b":1}}`).
- **Order-normalized (intended equivalence):** two objects differing only in key order ARE equal by design — this is
  correct (JSON object key order is not semantic); array order is preserved.

## 4. Domain separation (separate from canon)
`canon()` produces the message; cross-protocol separation is provided by the ML-DSA-87 **context** parameter (one
distinct `trelyan-*-v1` context per signing surface — see `domain-separation.mjs`, 23 distinct, 0 reuse, 0 bare). So
even if two modules' canon outputs were byte-identical, the context makes the signatures non-interchangeable; and the
contexts are proven distinct. Context is load-bearing AND redundant with per-module core shapes.

## 5. Known limitations / auditor questions
- **A SECOND serializer exists: the `pqsign` Signed Tree Head (council/Grok red-team).** `signedTreeHead`/`verifySTH`
  sign `JSON.stringify({tree_size, root, ts})` — a **fixed-key-order object literal**, NOT `canon()`. It is deterministic
  (the literal fixes key order) and signer==verifier, so it is sound; but it is a distinct serialization from `canon()`.
  Consequences an auditor/second-language implementer must note: (a) the `canon-determinism` "consistent across modules"
  check covers `canon()` call sites, **not** the STH literal; (b) `pqkt`/`pqvault` reuse this same STH core (they call
  `pqsign`'s log) — so all STHs share this literal form; (c) a cross-impl must reproduce **this exact key order**
  (`tree_size`,`root`,`ts`), not canon's sorted order. *Tracked decision: migrating the STH to `canon()` would unify on
  one serializer but re-pins `spine-vectors.mjs`.*
- **Not a certified RFC 8785 (JCS) implementation.** Number canonicalization differs from JCS's ECMAScript `Number`
  rules; we sidestep this by **restricting signed cores to integers** (no floats) — confirm no float ever enters a
  signed core (the `canon-determinism` value-domain contract + module review). The PQEF production profile uses
  deterministic CBOR (RFC 8949 §4.2) instead; `statement.canonicalization` records which profile.
- `sort()` uses JS default UTF-16-code-unit ordering. A second-language implementation MUST sort by the same order
  (UTF-16 code units, not locale, not Unicode-normalized) to reproduce bytes — auditors should confirm the
  cross-language note in `SPINE_SPEC.md`.
- Duplicate keys cannot occur in a JS object (last wins at parse); a wire format that allowed duplicate keys would need
  explicit rejection before `canon()` — out of scope for in-process objects, in scope for any future wire parser.
