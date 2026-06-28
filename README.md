# Falcon-on-Algorand Interop Conformance Kit

A small, reusable kit to prove that two independent Falcon-1024 signers emit
**byte-compatible signatures for the Algorand AVM `falcon_verify` opcode**, and to run
a joint **PQ object + authority** demo — one Falcon keypair that both *spends*
(algo-pqc-kit `FalconLsig`) and *inscribes* (trelyan-pq write-once record), with **no
Ed25519 in the authorization path**.

> Built to settle the trelyan-pq × algo-pqc-kit encoding question the only authoritative
> way — on-chain bytes — and to give any two Falcon-on-Algorand projects a shared
> conformance harness instead of a header-byte argument.

## The encoding verdict (adjudicated by a multi-model panel + the Falcon ref)

| Item | Resolution |
|---|---|
| `0xBA` header | **`0x3A | 0x80`** — standard Falcon-1024 compressed header `0x3A` (high-nibble compressed, low-nibble logn 10) + trelyan-pq's `0x80` deterministic-wrapper bit, then a `0x00` version byte. The `0x80`/`0x00` are a **project convention, not a NIST Falcon / FIPS-206 field** — so "non-standard" was a fair flag; it's a documented wrapper the opcode accepts. Never call it "the FN-DSA header." |
| `≤1423` vs `≤1232` | trelyan-pq's **contract** enforces `len(sig) ≤ 1423` (literally `pushint 1423; <=; assert` in app 763809096's TEAL); the measured sig is **1236 B**. The AVM opcode itself has **no** sig-length check (go-algorand `opFalconVerify` checks only the 1793-B pubkey; bound = `CTSignatureSize`). So `[1232]byte` is a nominal annotation and `≤1232` is simply tighter than this deployed contract. |
| Does the opcode get `0xBA`? | **Yes — read from the bytecode.** The contract strips only the 2-byte ABI prefix (`extract 2 0`); across all 405 TEAL lines there is **no** header-stripping op, and `falcon_verify` is `assert`-ed. |
| Who's right | **On-chain acceptance is the authority.** App **763809096** passes `falcon_verify` with these bytes (the write-once `i_` box was written) → empirically AVM-valid. The remaining interop question is just whether algo-pqc-kit's signer emits the same bytes — a shared KAT settles it. |

## The three checks (definitive reconciliation)

1. **On-chain byte inspection** — `onchain_probe.py` pulls app 763809096's calls and prints
   the real header byte / length hitting the contract (the dispositive read).
2. **Shared KAT** — `kat/*.json` pins one golden `(message, sig, pubkey, txid)`. Any signer
   that reproduces it byte-for-byte from the same key+message is conformant (`falcon_interop.py`).
3. **TestNet round-trip** — each project `falcon_verify`s the other's signature on-chain.

## What's in here

A small suite that turns "we can verify post-quantum trust on-chain" into usable tools.
Everything is honest about TestNet/unaudited scope and about what is standard vs. trelyan-pq
convention. The byte-level spec is in [`SPEC.md`](SPEC.md).

**Conformance core (Python)**
| File | What it does |
|---|---|
| `falcon_interop.py` | `inspect()` a Falcon sig, `compare()` two signers (localizes a diff to header/body), `abi_decode_bytes`, load+validate a KAT. CLI: `inspect`/`compare`/`kat`. |
| `onchain_probe.py` | Dumps the Falcon bytes hitting `falcon_verify` on-chain (needs `py-algorand-sdk`). |
| `kat/*.json` | Golden vectors. `…onchain.json` is real (from app 763809096) and now **offline-reproducible**; `…example.json` is a template. Variable length — do not hard-code a fixed size. |
| `kat/verify_onchain_kat.py` | Independently re-verifies the on-chain golden vector OFFLINE: rebuilds the 102-byte signed message (`DOMAIN_TAG‖app_id‖cell_id‖artifact_hash‖genesis_hash`) and confirms the Falcon-1024 signature over it (and that a hash-only or 1-bit-flipped message is rejected) against the public `algorand/falcon` lib. |
| `test_interop_demo.py` | Joint demo as a `pytest` skeleton (FalconLsig → inscribe → write-once). |

**SDK (`packages/verify-pqc/`)** — dependency-free JS, Node + browser: `inspectFalconSig`,
`abiDecodeBytes`, `compareSigs`, `verifyOnChain(appId)`. `node test.js` runs unit + a live check.

**Web tools (`web/`)** — drop-in, in-browser, no backend:
| File | What it does |
|---|---|
| `verify-live.html` | Enter an app-id → query the indexer → decode the Falcon sig → render the verdict. |
| `verify-unified.html` | One input: an app-id/txid (on-chain PQC) **or** a THRONDAR receipt (AI provenance). |
| `pqbadge.js` + `pqbadge-demo.html` | `<span data-pq-app="…">` + one script → a live "verified on-chain" pill. |
| `anchor.html` | The two-layer anchor log: THRONDAR's STH ↔ the Algorand Falcon inscription. |

**Two-layer anchor (`anchor/`)** — `anchor_sth.py prepare|verify`: bind THRONDAR's
transparency-log signed tree head to a Falcon inscription. Prepares + verifies only; the
Falcon-sign + inscribe step is a gated owner action (no key is read or used here).

## Run

```bash
python falcon_interop.py inspect my_sig.hex
python falcon_interop.py compare trelyan_sig.hex apk_sig.hex      # same key+message
python onchain_probe.py --app 763809096 --indexer https://testnet-idx.algonode.cloud
node packages/verify-pqc/test.js                                  # SDK unit + live test
python anchor/anchor_sth.py prepare                              # compute a live anchor commitment
# open web/verify-live.html or web/anchor.html in a browser
```

## To make the demo live (3 adapters in `test_interop_demo.py`)

1. `make_falcon_keypair()` → `(pubkey_1793, signer)` — TRELYAN's `falcon_det1024.py`, **or**,
   once KAT-aligned, algo-pqc-kit's pure-Python/Rust signer (drops the C dependency).
2. `derive_falconlsig_address(pk)` — algo-pqc-kit `FalconLsig`.
3. `build_inscribe_txn(...)` — trelyan-pq `inscribe(cell, commit, sig, uri)` ABI.

Then publish a real `kat/*.json` and open the demo PR against `quantalabss/algo-pqc-kit`.

## License & credit

MIT, commons-first. Co-developed by **TRELYAN** and **algo-pqc-kit (quantalabss)**;
keep `Signed-off-by` on commits and credit both projects in the demo PR.
*Note:* don't over-claim "first" — describe it as a **reference implementation** of a
PQ object+authority flow on Algorand.

> ⚠️ Do not modify the deployed contract / ABI / box prefixes of app 763809096. This kit
> only reads the chain and adds test/tooling around the existing interface.
