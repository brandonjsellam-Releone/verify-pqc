"""
anchor_sth.py — the TWO-LAYER ANCHOR.

Bind THRONDAR's transparency-log Signed Tree Head (RFC-6962, ML-DSA-87 signed) to an
Algorand Falcon-1024 inscription, so AI-answer trust is anchored on a public post-quantum
chain. Forging the record then requires breaking BOTH layers — the ML-DSA STH AND a
write-once Falcon inscription on an immutable public ledger.

This tool only PREPARES and VERIFIES anchors. It never reads a private key, signs, spends,
or deploys — the Falcon-sign + inscribe step is an explicit OWNER action (gated).

  prepare           fetch the live STH, compute the domain-separated anchor commitment,
                    and emit the inscribe parameters (dry-run).
  verify <record>   recompute the commitment from a saved anchor record; with --txid, also
                    check it equals the on-chain inscription's 32-byte commit.

Usage:
  python anchor_sth.py prepare --out anchor-<ts>.json
  python anchor_sth.py verify anchor-<ts>.json --txid <ALGOTXID>
"""
from __future__ import annotations
import argparse, base64, hashlib, json, struct, urllib.request

THRONDAR = "https://throndar.ai"
INDEXER = "https://testnet-idx.algonode.cloud"
DOMAIN = b"TRELYAN-ANCHOR-v1"
APP = 763809096  # the canonical deployed inscription app (we USE its inscribe; we never alter it)
RECOGNIZED_APPS = {"763809096", "764917520"}  # TRELYAN inscription contracts whose TEAL gates the i_ box on falcon_verify
INSCRIBE_SELECTOR = "9d300cf2"  # inscribe(cell, commit, sig, uri) ABI method selector — commit is arg[2]


def sha512_256(b: bytes) -> bytes:
    return hashlib.new("sha512_256", b).digest()


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "trelyan-anchor/0.1"})
    return urllib.request.urlopen(req, timeout=20).read()


def fetch_sth() -> dict:
    data = json.loads(_get(THRONDAR + "/api/transparency/ledger"))
    sth = data.get("signed_tree_head", {}) or {}
    signed = sth.get("signed")
    fields = json.loads(signed) if isinstance(signed, str) else (signed or {})
    return {
        "log": fields.get("log") or data.get("log"),
        "tree_size": int(fields.get("tree_size", data.get("tree_size", 0))),
        "root_hash": fields.get("root_hash") or data.get("root_hash"),
        "timestamp": int(fields.get("timestamp", 0)),
        "sth_signed": signed,                               # exact bytes the STH signature covers
        "sth_sig": (sth.get("receipt") or {}).get("sig"),   # ML-DSA-87 signature (hex)
        "sth_algo": data.get("algo"),
    }


def anchor_commitment(sth: dict):
    """Domain-separated commitment over the canonical STH fields. Deterministic + length-framed."""
    root = bytes.fromhex(sth["root_hash"])
    payload = (
        DOMAIN + b"\x00"
        + sth["log"].encode("utf-8") + b"\x00"
        + struct.pack(">Q", sth["tree_size"])
        + root
        + struct.pack(">Q", sth["timestamp"])
    )
    return sha512_256(payload), payload


def cmd_prepare(args):
    sth = fetch_sth()
    commit, payload = anchor_commitment(sth)
    rec = {
        "anchor_version": "TRELYAN-ANCHOR-v1",
        "sth": sth,
        "commitment_sha512_256": commit.hex(),
        "commitment_preimage_hex": payload.hex(),
        "inscribe": {
            "app_id": APP,
            "network": "testnet",
            "commit_arg_hex": commit.hex(),
            "owner_step": ("GATED: Falcon-sign this 32-byte commit with the trelyan-pq key, then call "
                           "inscribe(cell, commit, sig, uri). No key is read, used, or required here."),
        },
        "verify": "sha512_256(commitment_preimage) == commitment_sha512_256 == the inscription's 32-byte commit arg on-chain.",
    }
    js = json.dumps(rec, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(js)
        print("wrote", args.out)
    print(js)


def cmd_verify(args):
    with open(args.record, encoding="utf-8") as f:
        rec = json.load(f)
    commit, _ = anchor_commitment(rec["sth"])
    rec_ok = commit.hex() == rec.get("commitment_sha512_256")
    print("recomputed commitment :", commit.hex())
    print("matches saved record  :", rec_ok)
    if args.txid:
        t = json.loads(_get(INDEXER + "/v2/transactions/" + args.txid))
        at = (t.get("transaction", {}).get("application-transaction", {}) or {})
        app_id = str(at.get("application-id", ""))
        decoded = [base64.b64decode(a) for a in at.get("application-args", [])]
        selector = decoded[0].hex() if decoded else ""
        commit_arg = decoded[2].hex() if len(decoded) > 2 and len(decoded[2]) == 32 else None
        reasons = []
        if app_id not in RECOGNIZED_APPS:
            reasons.append(f"txn app {app_id} is not a recognized TRELYAN contract")
        if selector != INSCRIBE_SELECTOR:
            reasons.append("txn is not an inscribe() call")
        if commit_arg != commit.hex():
            reasons.append("on-chain commit arg does not match this tree head")
        chain_ok = not reasons
        print("on-chain app / call   :", app_id, "/", ("inscribe" if selector == INSCRIBE_SELECTOR else (selector or "(none)")))
        print("on-chain commit arg   :", commit_arg)
        verdict = bool(rec_ok and chain_ok)
        print("LAYER-2 VERIFIED       :", verdict, ("" if verdict else "-> " + "; ".join(reasons)))
        print("NOTE: confirms Layer 2 (a recognized contract inscribed this commitment via inscribe()).")
        print("      It does NOT verify the Layer-1 ML-DSA-87 STH signature (sth_sig) — cross-check that")
        print("      independently at", THRONDAR + "/api/transparency/ledger")
    else:
        print("(pass --txid <ALGOTXID> to also check the on-chain inscription)")


def main():
    p = argparse.ArgumentParser(description="Two-layer anchor: THRONDAR STH <-> Algorand Falcon inscription.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prepare"); pp.add_argument("--out"); pp.set_defaults(fn=cmd_prepare)
    pv = sub.add_parser("verify"); pv.add_argument("record"); pv.add_argument("--txid"); pv.set_defaults(fn=cmd_verify)
    args = p.parse_args(); args.fn(args)


if __name__ == "__main__":
    main()
