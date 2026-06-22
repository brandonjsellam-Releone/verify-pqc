# Draft reply — algo-pqc-kit interop (post when you're ready)

> Paste target: the quantalabss/algo-pqc-kit thread. This is a DRAFT for you to post — not auto-sent.
> It now leads with on-chain + published evidence, not a header-byte argument.

---

@XD637 — thanks, and congrats on the move to quantalabss. Let me close the encoding item the only way that's actually authoritative — on-chain bytes — and then propose the demo. I've put everything below into an open MIT kit so none of it is hand-waving.

**Encoding — settled on-chain, twice.** trelyan-pq's deterministic Falcon-1024 signatures verify through the live `falcon_verify` opcode on TestNet — first on app **763809096** (the inscription app), and again just now on a fresh sandbox app **764917520** ([txn `HII5Z3MO…`](https://lora.algokit.io/testnet/transaction/HII5Z3MONXKT6D4O5NGZ677DMMFW5BCMQVIUTFNN532O5KLBPLYQ)), where `falcon_verify` gated a write-once inscription. So the exact bytes my signer emits are AVM-accepted today — that's the fixed point everything reconciles to.

**On the `0xBA` header — and where you were right.** `0xBA = 0x3A | 0x80`: the `0x3A` is the standard NIST Round-3 compressed Falcon-1024 header (high-nibble compressed, low-nibble logn 10); the `0x80` high bit plus a following `0x00` version byte are **trelyan-pq's deterministic-wrapper convention — a project extension, not a NIST/FIPS-206 (FN-DSA) field.** So your "non-standard" flag was fair — I should never have implied it's "the FN-DSA header," and the kit's docs now say so explicitly. The opcode accepts it because go-algorand `opFalconVerify` doesn't gate on header semantics — it length-checks only the 1793-byte pubkey and bounds the sig by `CTSignatureSize`; there is **no `≤1232` check** in the opcode. The `≤1423` is *my contract's* enforced ceiling (literally `pushint 1423` in its TEAL), and the measured on-chain sig is **1236 B** — so `≤1232` would actually reject valid signatures the deployed contract accepts.

So the reconcile isn't "who's right" — it's "do both signers emit AVM-accepted bytes." Three checks, all scripted in the kit:

1. **On-chain byte inspection** — `onchain_probe.py` dumps the exact app-arg bytes hitting `falcon_verify` (it confirms the contract strips only the 2-byte ABI prefix, never the header).
2. **Shared KAT** — a golden `(message, sig, pubkey, txid)` from a real inscription; any signer that reproduces it byte-for-byte from the same key+message is conformant (`falcon_interop.py compare`). If `falcon-multisig` matches, I'll happily drop my C dependency for your signer (credited). If not, the diff localizes the divergence to {header bit, salt handling, body} in one shot.
3. **TestNet round-trip** — each project `falcon_verify`s the other's signature on-chain. On-chain acceptance is the only authority.

**The kit (MIT, public):** github.com/brandonjsellam-Releone/verify-pqc — a dependency-free JS SDK (`@trelyan/verify-pqc` on npm, `verifyOnChain(appId)`), in-browser verifiers, the conformance core + golden KATs, and the on-chain probe. Reuse any of it.

**The demo I'd love to build with you:** one Falcon-1024 keypair across both layers — a `FalconLsig` (algo-pqc-kit) authorizes the txn that calls `trelyan-pq.inscribe()`, which `falcon_verify`s the same key's signature and writes a write-once record. A clean end-to-end post-quantum object+authority flow with no Ed25519 in the path. I'll do the legwork — a `pytest` (derive the LSig address → fund + authorize via the LSig → inscribe → assert the box is write-once), opened as a PR against quantalabss once we've KAT-aligned, crediting both projects.

Reciprocal review on your `FalconLsig` derivation + `PQCDao` call sites is on offer whenever useful. Worth a 20-minute call to scope the KAT + demo?

— Brandon
