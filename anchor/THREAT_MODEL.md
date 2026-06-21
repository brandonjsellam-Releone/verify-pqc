# Two-layer anchor — threat model

Adversarial analysis of binding THRONDAR's transparency-log signed tree head (STH) to an
Algorand Falcon-1024 inscription. Honest scope: **TestNet, unaudited.** This is an engineering
analysis pending independent review, not a proof.

## Construction

- **Layer 1 (THRONDAR).** An RFC-6962 log of post-quantum-signed AI answers. The STH
  `{log, tree_size, root_hash, timestamp}` is signed with **ML-DSA-87** (key `0986d89fa3c74566`).
- **Layer 2 (Algorand).** `commitment = sha512_256("TRELYAN-ANCHOR-v1" ‖ log ‖ u64be(tree_size)
  ‖ root_hash ‖ u64be(timestamp))`, inscribed **write-once** via app `763809096` and accepted
  on-chain by `falcon_verify` (Falcon-1024).
- **Binding.** The commitment ties one specific STH to one immutable on-chain record, dated by
  the Algorand block.

## Adversary model — what each compromise does and does not break

| Adversary capability | Effect | Why the anchor holds |
|---|---|---|
| **Forge ML-DSA STHs only** (Layer-1 key) | Can mint fake STHs with valid signatures. | They are not *anchored*: a fake STH has no matching on-chain commitment, and **already-anchored honest heads are immutable on-chain** and cannot be rewritten. `verify` rejects an "anchored" claim with no chain match. |
| **Inscribe arbitrary commitments only** (Layer-2 key) | Can write junk commitments on-chain. | A commitment only validates as a THRONDAR anchor if its STH also carries a valid **ML-DSA** signature. Inscribing a commitment to an unsigned/fake STH fails verification. |
| **Both keys** | Can produce a self-consistent fake (signed STH + matching inscription). | This is the **irreducible trust floor**. The design's value is raising the bar from one key to **two independent post-quantum keys on two independent systems**. |
| **Algorand reorg** (TestNet) | A *recent* anchor could un-confirm. | Wait for finality before relying on an anchor; the write-once box prevents overwrite, not reorg. TestNet caveat is stated. |
| **Compromise/MITM one indexer** | A verifier reading that indexer sees a false view. | Query multiple indexers / run your own; the tools disclose single-indexer trust. |

## What the second layer *adds*

1. **Equivocation resistance.** RFC-6962's classic weakness is a log showing different histories
   to different clients (split-view). Once an STH is anchored on a public chain, **everyone sees
   the same anchored root** — the chain is the witness/gossip layer. Caveat: this holds only for
   *anchored* heads; entries between anchors are still equivocable, so **anchor cadence is a
   security parameter** (shorter interval → smaller equivocation window).
2. **Independent timestamp.** The Algorand block time is an external lower bound — the anchored
   answers existed no later than that block — stronger than THRONDAR's self-asserted `timestamp`.
3. **Censorship-resistant availability.** If THRONDAR's API is down, anchored heads remain
   queryable from the chain via any indexer.

## Commitment security

- **Hash:** `sha512_256` — 256-bit, collision-resistant; ~128-bit against Grover (adequate PQ margin).
- **Domain separation:** the `"TRELYAN-ANCHOR-v1"` prefix prevents cross-protocol preimage reuse.
- **Unambiguous encoding:** `\0`-delimited ASCII log name + **fixed-width** `u64be` for `tree_size`
  and `timestamp` + fixed 32-byte root → no canonicalization/length-extension ambiguity.

## What the anchor does NOT prove

- It commits to the **tree head**, not to any single answer. To prove a specific answer is in the
  anchored log, pair the anchor with an **RFC-6962 inclusion proof** against that root
  (`/api/transparency/ledger/inclusion`). Anchor + inclusion proof together = "this answer was in
  the log when it was anchored on-chain."
- It does **not** check the ML-DSA STH signature itself — a verifier must do that independently.
  The anchor proves "this root was anchored at time T"; the ML-DSA signature proves "THRONDAR
  vouched for this root." Both are required.

## Residual assumptions
TestNet + unaudited system · security of the ML-DSA and Falcon keys (the 2-key floor) · honest
indexer (or query several) · anchor cadence bounds the equivocation window · `falcon_verify`
and the deployed contract behave as observed (see `../SPEC.md`).
