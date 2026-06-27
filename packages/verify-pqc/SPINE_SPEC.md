# TRELYAN Transparency Spine — formal specification (audit input)

The **spine** is the shared, append-only, signed-Merkle transparency layer in `pqsign.mjs`. It is the root of trust
reused by `pqtsa` (timestamp anchoring), `pqkt` (key-transparency log), `pqvault` (manifest), and `pqinduct`
(induction log). This spec defines its byte-level behaviour precisely enough for an independent re-implementation;
pinned conformance vectors are in `spine-vectors.mjs`.

> **AUDIT STATUS — UNAUDITED REFERENCE DESIGN.** This spec defines *intended* behaviour. The implementation has NOT
> had a third-party crypto/side-channel audit. Verifying spec↔implementation conformance is part of the audit scope;
> any deviation is a bug. Do not treat this document as an assurance claim.

## 1. Primitives
- Hash: **SHA-256** (`@noble/hashes/sha2`). `‖` = byte concatenation.
- STH signature: **ML-DSA-87** (FIPS 204, `@noble/post-quantum/ml-dsa`), domain-separation context = ASCII
  `trelyan-pqsign-sth-v1`; artifact-attestation context = `trelyan-pqsign-attestation-v1`.
- Canonical bytes for signed structures: `canon(v)` = JSON with **recursively sorted object keys**, minimal
  separators (`{"k":v,...}`), standard JSON scalar encoding; then UTF-8.

## 2. Merkle tree (RFC-6962 §2.1)
- **Leaf hash:** `LH(entry) = SHA-256( 0x00 ‖ UTF8(canon(entry)) )` — the entry is serialized with the SAME canonical
  JSON as the STH (`canon` = recursively sorted keys, minimal separators), NOT `JSON.stringify`. (Council fix: leaves
  must be canonical for cross-implementation determinism; one shared `entryLeafHash` is used by the spine + every
  consumer.) Implementations in other languages MUST canonicalize identically.
- **Node hash:** `NH(l, r) = SHA-256( 0x01 ‖ l ‖ r )`.
- **Root** `MTH(D[0:n])`: empty → `SHA-256("")`; n=1 → `LH(d0)`; else split at the **largest power of two `k < n`**,
  `MTH = NH( MTH(D[0:k]), MTH(D[k:n]) )`. (Implementation builds bottom-up, promoting a lone right node unchanged;
  equivalent to the top-down split.)

## 3. Inclusion proof (RFC-6962 §2.1.1) — **bound to (index, tree_size)**
`verifyInclusionRFC(leaf, index, treeSize, auditPath, root) -> bool`:
```
if not (0 <= index < treeSize): return false
fn = index; sn = treeSize - 1; r = leaf
for p in auditPath:
    if sn == 0: return false                      # proof too long
    if (fn & 1) or (fn == sn):
        r = NH(p, r)
        while (fn & 1) == 0 and fn != 0: fn >>= 1; sn >>= 1   # rightmost-node case
    else:
        r = NH(r, p)
    fn >>= 1; sn >>= 1
return sn == 0 and r == root                       # exact proof length + root match
```
Directions are **derived from (index, treeSize)**, never trusted from the proof. Consumers MUST also require
`inclusion.tree_size == signedSTH.tree_size` and **recompute the leaf** from the object (never trust a supplied leaf).

## 4. Consistency proof (RFC-6962 §2.1.2) — append-only / no-rewrite
`verifyConsistency(m, n, root1, root2, proof) -> bool` (m ≤ n): proves tree@m is a prefix of tree@n.
```
if not (1 <= m <= n): return false
if m == n: return proof == [] and root1 == root2
path = (m is a power of 2) ? [root1] ++ proof : proof
fn = m-1; sn = n-1
while fn & 1: fn >>= 1; sn >>= 1
fr = sr = path[0]
for c in path[1:]:
    if sn == 0: return false
    if (fn & 1) or (fn == sn):
        fr = NH(c, fr); sr = NH(c, sr)
        while (fn & 1) == 0 and fn != 0: fn >>= 1; sn >>= 1
    else:
        sr = NH(sr, c)
    fn >>= 1; sn >>= 1
return sn == 0 and fr == root1 and sr == root2
```

## 5. Signed Tree Head (STH)
`STH = { tree_size, root_hex, ts }`, signature = `ML-DSA-87.sign( canon({tree_size, root: root_hex, ts}), sk, ctx=sth-v1 )`.
`verifySTH` recomputes `canon` and verifies under the **pinned** log public key. The root in the STH MUST equal `MTH`
of the first `tree_size` leaves (conformance vector confirms `sth_root == root@7`).

## 6. Required consumer obligations (where the security actually lives)
1. **Pin** the log/issuer public key out-of-band; never trust a key carried by the artifact.
2. **Recompute** the leaf with `canon` from the object; require `tree_size` match between inclusion and the signed STH.
3. **Check the index**: position-binding only holds if the consumer verifies the leaf is at the *expected* index
   (for ordered data) or the *latest* index for the subject (for "current state"). The proof binds (leaf, index,
   tree_size) — the consumer must supply the index it expects, not accept whatever is presented.
4. For "is this current?" questions (key state, vault entry): take the **latest** leaf for the subject within the
   signed tree AND require a **FRESH** STH. ⚠️ Rollback/freshness resistance is **conditional** on obtaining a fresh,
   consistency-checked STH via **gossip/witnesses** — a single log can present an internally-consistent stale view.
   (See THREAT_MODEL; `witness-service.mjs` is the witness node.)

## 7. Conformance vectors (`spine-vectors.mjs`, pinned)
Fixed 7-leaf tree, entries `{"v":"spine-leaf-i"}` for i=0..6; STH key = ML-DSA-87 keygen(seed=0x2A×32); STH ts=1700000000.
- `leaf[0] = SHA-256(0x00 ‖ '{"v":"spine-leaf-0"}')` = `78446ff5…79e2b9`
- `root@3` = `e5f07204…6770b3` · `root@4` = `a4bbdc3e…c3d47c` · `root@7` = `85d5836f…2d3bc6` (= signed STH root)
- Inclusion verifies for every index 0..6; consistency verifies for every prefix m=1..7 → 7.
An independent implementation MUST reproduce these hex values. `vectors-crosscheck.mjs` additionally differential-tests
an independent from-scratch RFC-6962 reference against the optimized verifiers over 42,574 size/index/prefix cases.

## 8. Security properties claimed
- **Append-only** (consistency proofs) and **tamper-evidence** (STH signature + canonical leaf rebind) — hold against
  a log presenting a single self-consistent view.
- **Position-binding** (inclusion bound to index+tree_size) — holds **only if** the consumer checks the index it
  expects (§6.3).
- **Rollback/freshness resistance for "current state"** — **CONDITIONAL**: holds only when the consumer obtains a
  fresh, consistency-checked STH via gossip/witnesses (§6.4). A single log alone does NOT provide it.
NOT claimed: completeness/split-view resistance for a single log (needs witnesses); constant-time execution; that
canonical JSON is collision-free across maliciously-crafted distinct objects beyond what sorted-key canon guarantees.
