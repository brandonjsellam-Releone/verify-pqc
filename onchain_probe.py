"""
onchain_probe.py — the DISPOSITIVE encoding check (per Team Apex / Grok red-team).

The only authority on "which Falcon bytes the AVM accepts" is the bytes that actually
reached the `falcon_verify` opcode in a SUCCESSFUL on-chain call. This probe pulls the
application-call transactions for the trelyan-pq inscription app, extracts the
signature application-argument, and inspects its real header byte / length — so the
encoding claim is *shown from chain data*, never merely asserted.

Two levels of rigor:
  (A) app-arg extraction (default)   — what the caller PASSED to the contract.
  (B) dryrun/simulate TEAL trace     — what the opcode actually CONSUMED (catches a
                                        contract that strips/extracts the header first).
Level B is the gold standard; (A) is enough to confirm the header byte when the
contract forwards the arg unchanged (TRELYAN's does — confirm in your TEAL).

Requires: pip install py-algorand-sdk
Usage:
    python onchain_probe.py --app 763809096 \
        --indexer https://testnet-idx.algonode.cloud --network testnet
"""
from __future__ import annotations

import argparse
import base64
import json

import falcon_interop as F

# Falcon-1024 signature length window (compressed): generous bounds, NOT a hard cap.
SIG_MIN, SIG_MAX = 600, 1500
PUBKEY_LEN = F.PUBKEY_LEN_1024  # 1793


def _looks_like_sig(b: bytes) -> bool:
    return SIG_MIN <= len(b) <= SIG_MAX and (b[0] & F.LOGN_MASK) == F.LOGN_1024


def probe(app_id: int, indexer_url: str, indexer_token: str = "", limit: int = 25) -> list[dict]:
    from algosdk.v2client import indexer

    idx = indexer.IndexerClient(indexer_token, indexer_url)
    resp = idx.search_transactions(application_id=app_id, limit=limit)
    findings: list[dict] = []
    for txn in resp.get("transactions", []):
        appl = txn.get("application-transaction") or {}
        for i, b64 in enumerate(appl.get("application-args", [])):
            raw = base64.b64decode(b64)
            dec = F.abi_decode_bytes(raw)            # strip ABI byte[] length prefix
            if _looks_like_sig(dec):
                info = F.inspect(dec)
                findings.append({
                    "txid": txn.get("id"),
                    "round": txn.get("confirmed-round"),
                    "arg_index": i,
                    "abi_prefixed": len(dec) != len(raw),
                    "header_byte": info.header_hex,
                    "sig_len": info.total_len,
                    "deterministic": info.deterministic,
                    "fmt": info.fmt,
                    "notes": info.notes,
                })
            elif len(dec) == PUBKEY_LEN:
                findings.append({"txid": txn.get("id"), "arg_index": i,
                                 "pubkey_len": len(dec), "note": "Falcon-1024 public key (1793B)"})
    return findings


def main() -> None:
    p = argparse.ArgumentParser(description="Dump the Falcon bytes hitting falcon_verify on-chain.")
    p.add_argument("--app", type=int, required=True)
    p.add_argument("--indexer", default="https://testnet-idx.algonode.cloud")
    p.add_argument("--token", default="")
    p.add_argument("--limit", type=int, default=25)
    a = p.parse_args()
    out = probe(a.app, a.indexer, a.token, a.limit)
    print(json.dumps(out, indent=2))
    headers = {f["header_byte"] for f in out if "header_byte" in f}
    print("\n=== VERDICT ===")
    if not out:
        print("No matching app-args found — widen --limit or check the app id / indexer.")
    elif headers == {"0xba"}:
        print("CONFIRMED on-chain: signatures hitting the contract carry header 0xBA "
              "(deterministic compressed Falcon-1024). For full rigor, also run a dryrun "
              "trace to confirm the opcode consumes these bytes unchanged (no header strip).")
    elif headers:
        print(f"On-chain header byte(s) observed: {sorted(headers)}. If this is NOT 0xBA, "
              "your contract likely transforms the arg before falcon_verify — inspect the "
              "TEAL (look for extract/substring on the sig) before claiming the opcode header.")


if __name__ == "__main__":
    main()
