"""
test_interop_demo.py — the joint demo, as a runnable pytest skeleton.

One Falcon-1024 keypair controls BOTH layers:
  * algo-pqc-kit  FalconLsig  — derives an Algorand address; gates SPENDING via falcon_verify.
  * trelyan-pq    inscription — write-once record; gates the INSCRIPTION via falcon_verify.

The end-to-end flow (no Ed25519 in the authorization path):
  1. generate ONE Falcon-1024 keypair
  2. derive the FalconLsig address from its public key            (algo-pqc-kit)
  3. fund the LSig address                                        (dispenser / funded acct)
  4. register the pubkey into the inscription box                 (trelyan-pq, one-time)
  5. build inscribe(cell, commit=sha512_256(artifact), sig, uri)  — sig over the commitment
  6. authorize + send that txn FROM the FalconLsig                (LogicSig signs the txn)
  7. assert the box now exists and is WRITE-ONCE (re-inscribe -> rejected)

This file is a SCAFFOLD: the three `TODO:` adapters are the only project-specific glue.
Fill them from your SDKs and the demo runs green. Until then it SKIPS with an actionable
message (so CI stays green and the intent is documented).

Run:  pytest test_interop_demo.py -v          (or -s to see the trace)
Env:  ALGOD_URL, ALGOD_TOKEN, FUNDER_MNEMONIC, TRELYAN_APP_ID=763809096
"""
from __future__ import annotations

import hashlib
import os

import pytest

APP_ID = int(os.environ.get("TRELYAN_APP_ID", "763809096"))
ALGOD_URL = os.environ.get("ALGOD_URL", "https://testnet-api.algonode.cloud")
ALGOD_TOKEN = os.environ.get("ALGOD_TOKEN", "")
FUNDER_MNEMONIC = os.environ.get("FUNDER_MNEMONIC", "")


def sha512_256(b: bytes) -> bytes:
    """Algorand's hash (the inscription commitment uses it)."""
    return hashlib.new("sha512_256", b).digest()


# --------------------------------------------------------------------------- #
# Project-specific adapters — the ONLY glue to fill in. Keep raw bytes flowing.
# --------------------------------------------------------------------------- #
def make_falcon_keypair():
    """TODO: return (pk_bytes_1793, signer) where signer(msg)->det-Falcon-1024 sig (0xBA).
    Use TRELYAN's contracts/falcon_det1024.py, OR — once KAT-aligned — algo-pqc-kit's
    pure-Python/Rust signer to drop the C dependency. Both must pass the shared KAT."""
    pytest.skip("adapter make_falcon_keypair() not wired — see kat/ to pick the signer")


def derive_falconlsig_address(pk: bytes) -> str:
    """TODO: algo-pqc-kit FalconLsig: address = base32(sha512_256('Program'||lsig)+cksum).
    Return the Algorand address string the LSig spends from."""
    pytest.skip("adapter derive_falconlsig_address() not wired — algo-pqc-kit FalconLsig")


def build_inscribe_txn(app_id, sender, commit32, sig, uri, sp):
    """TODO: build the ApplicationCall to trelyan-pq inscribe(cell, commit, sig, uri).
    Pass `sig` (and pubkey-in-box per registration) as raw app-args — do NOT re-encode.
    Return an unsigned Transaction."""
    pytest.skip("adapter build_inscribe_txn() not wired — trelyan-pq inscribe ABI")


# --------------------------------------------------------------------------- #
# The demo.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def algod():
    if not (ALGOD_TOKEN is not None and ALGOD_URL):
        pytest.skip("no algod configured (set ALGOD_URL / ALGOD_TOKEN)")
    from algosdk.v2client import algod as _algod
    return _algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)


def test_falcon_keypair_passes_shared_kat():
    """Gate: whichever signer we use MUST reproduce the shared golden vector byte-for-byte."""
    import json
    import falcon_interop as F
    kat_path = os.path.join(os.path.dirname(__file__), "kat", "falcon1024_det.example.json")
    if not os.path.exists(kat_path):
        pytest.skip("no KAT file yet — publish one from app 763809096 first")
    kat = F.load_kat(kat_path)
    assert kat["_validation"]["ok"], kat["_validation"]["problems"]
    pk, signer = make_falcon_keypair()                      # skips until wired
    sig = signer(bytes.fromhex(kat["message_hex"]))
    cmp = F.compare(sig, bytes.fromhex(kat["sig_hex"]))
    assert cmp.identical, f"signer is NOT KAT-conformant: {cmp.summary}"


def test_one_falcon_key_authorizes_and_inscribes(algod):
    """The headline: one PQ key spends (FalconLsig) AND inscribes (trelyan-pq), write-once."""
    from algosdk import transaction

    pk, signer = make_falcon_keypair()                      # skips until wired
    lsig_addr = derive_falconlsig_address(pk)               # skips until wired

    # 3) fund the LSig address (TODO: dispenser or FUNDER_MNEMONIC pay txn) ...
    # 4) one-time pubkey registration into the inscription box (TODO) ...

    artifact = b"trelyan x algo-pqc-kit: fully-PQ object+authority flow"
    commit = sha512_256(artifact)
    sig = signer(commit)                                    # Falcon sig over the commitment
    uri = b"ipfs://<cid>"
    sp = algod.suggested_params()

    txn = build_inscribe_txn(APP_ID, lsig_addr, commit, sig, uri, sp)   # skips until wired
    # 6) authorize FROM the FalconLsig (LogicSig signs the txn) — no Ed25519:
    #    lsig = transaction.LogicSigAccount(lsig_program, args=[sig])   # TODO program+args
    #    signed = transaction.LogicSigTransaction(txn, lsig)
    #    txid = algod.send_transaction(signed); transaction.wait_for_confirmation(algod, txid, 4)

    # 7) write-once: the SAME inscribe must now be REJECTED.
    #    with pytest.raises(Exception):
    #        algod.send_transaction(transaction.LogicSigTransaction(txn, lsig))
    pytest.skip("flow scaffold complete — wire the 3 adapters + uncomment 3/4/6/7 to run live")
