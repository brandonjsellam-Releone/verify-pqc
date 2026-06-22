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

## What this kit's verifier checks (and what it does NOT)

`anchor.html` and `anchor_sth.py verify` confirm **Layer 2 only**, and exactly these three things:
1. the txn's app-id is a **recognized** TRELYAN inscription contract (`763809096`, `764917520`) —
   app-ids are chain-assigned and unforgeable;
2. the txn is an **`inscribe()`** call (method selector `9d300cf2`);
3. the **commit arg** (`inscribe`'s 3rd argument) equals `commitment(sth)` recomputed locally.

It does **NOT** re-run the **Layer-1 ML-DSA-87 STH signature** in-browser. A green ✓ therefore means
"a recognized TRELYAN contract inscribed this exact tree-head commitment via a `falcon_verify`-gated
call" — *not* that THRONDAR's ML-DSA signature over that STH is valid. **You must verify Layer 1
independently** (against THRONDAR's published answer-signer key / `/api/transparency/ledger`) for the
full two-layer guarantee. In-browser ML-DSA (WASM) re-verification is planned.

## Adversary model — what each compromise does and does not break

| Adversary capability | Effect | What actually stops it |
|---|---|---|
| **Forge ML-DSA STHs only** (Layer-1 key) | Mint fake STHs with valid-looking signatures. | The **independent Layer-1 check** (verify the ML-DSA sig against THRONDAR's published key) rejects a forged STH. ⚠️ The kit's verifier does NOT do this in-browser today, so a fake STH whose commitment the attacker also inscribes on a recognized app would display "Layer-2 verified" — run the Layer-1 check yourself until WASM ML-DSA ships. |
| **Inscribe arbitrary commitments only** (Layer-2 / Falcon capability) | Inscribe any commitment on a recognized app. | Only the **Layer-1 ML-DSA verification** binds a commitment to a *genuine* THRONDAR STH. Layer 2 alone (all the kit checks) proves a recognized contract inscribed the value, not that the STH is authentic. |
| **Both keys** | Self-consistent fake (signed STH + matching inscription). | **Irreducible trust floor** — two independent post-quantum keys on two independent systems. |
| **Algorand reorg** (TestNet) | A *recent* anchor could un-confirm. | Wait for finality before relying on an anchor; the write-once box prevents overwrite, not reorg. |
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
