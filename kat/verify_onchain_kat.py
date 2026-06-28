#!/usr/bin/env python3
"""
verify_onchain_kat.py — offline-reproduce the REAL on-chain Falcon-1024 golden vector.

This independently confirms that the signature in `falcon1024_det.onchain.json` (accepted by the
`falcon_verify` opcode on Algorand TestNet, app 763809096) verifies OFFLINE over the exact message
the contract reconstructs on-chain:

    M = DOMAIN_TAG("TRELYAN-INSCRIPTION-v1", 22B)
        || itob(app_id,   8B big-endian)
        || itob(cell_id,  8B big-endian)
        || artifact_hash (32B)
        || genesis_hash  (32B)                      # = 102 bytes

It uses ONLY public inputs: the KAT file + the public github.com/algorand/falcon C library
(the same deterministic Falcon-1024 implementation the AVM opcode is derived from). No TRELYAN
contract source is required — the message is rebuilt from the KAT's `message_components`.

------------------------------------------------------------------------------------------------
BUILD THE FALCON LIB (one-time), then point this script at it:

    git clone https://github.com/algorand/falcon && cd falcon
    cc -O3 -fPIC -shared -o libfalcondet1024.so \
        codec.c common.c falcon.c fft.c fpr.c keygen.c rng.c shake.c sign.c vrfy.c deterministic.c
    #   (Windows: build a .dll with the same sources; macOS: .dylib. A zig toolchain also works:
    #    `python -m ziglang cc -O3 -shared -o falcondet.dll <the same .c files>`.)
    export FALCON_DET1024_LIB="$PWD/libfalcondet1024.so"

RUN:
    python verify_onchain_kat.py            # exit 0 + "CONFIRMED" on success
------------------------------------------------------------------------------------------------
"""
from __future__ import annotations
import base64, ctypes, json, os, sys
from pathlib import Path

KAT = Path(__file__).with_name("falcon1024_det.onchain.json")
DOMAIN_TAG = b"TRELYAN-INSCRIPTION-v1"   # 22 bytes — contract DOMAIN_TAG


def _load_lib() -> ctypes.CDLL:
    path = os.environ.get("FALCON_DET1024_LIB") or "./libfalcondet1024.so"
    if not Path(path).exists():
        sys.exit(f"Falcon lib not found at {path!r}. Build github.com/algorand/falcon and set "
                 f"FALCON_DET1024_LIB to the .so/.dll/.dylib (see this file's header).")
    lib = ctypes.CDLL(path)
    lib.falcon_det1024_verify_compressed.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.falcon_det1024_verify_compressed.restype = ctypes.c_int
    return lib


def build_message(app_id: int, cell_id: int, artifact_hash: bytes, genesis_hash: bytes) -> bytes:
    assert len(artifact_hash) == 32 and len(genesis_hash) == 32
    return (DOMAIN_TAG + app_id.to_bytes(8, "big") + cell_id.to_bytes(8, "big")
            + artifact_hash + genesis_hash)


def verify(lib: ctypes.CDLL, sig: bytes, pubkey: bytes, data: bytes) -> bool:
    return lib.falcon_det1024_verify_compressed(sig, len(sig), pubkey, data, len(data)) == 0


def main() -> None:
    k = json.loads(KAT.read_text())
    c = k["message_components"]
    artifact_hash = bytes.fromhex(c["artifact_hash_hex"])
    genesis_hash = base64.b64decode(c["genesis_hash_b64"])
    sig, pubkey = bytes.fromhex(k["sig_hex"]), bytes.fromhex(k["pubkey_hex"])

    M = build_message(c["app_id"], c["cell_id"], artifact_hash, genesis_hash)
    # the reconstructed M must equal the pinned message_hex (independent cross-check)
    if M.hex() != k["message_hex"]:
        sys.exit("FAIL: rebuilt M != pinned message_hex — the KAT components are inconsistent.")

    lib = _load_lib()
    full = verify(lib, sig, pubkey, M)
    only = verify(lib, sig, pubkey, artifact_hash)           # the old 32B-hash guess: must be False
    tamper = bytearray(M); tamper[-1] ^= 1
    mut = verify(lib, sig, pubkey, bytes(tamper))            # 1-bit-flipped message: must be False

    print(f"app_id={c['app_id']} cell_id={c['cell_id']} txid={k.get('verified_txid')}")
    print(f"|M|={len(M)}B  sig={len(sig)}B (0x{sig[0]:02x})  pubkey={len(pubkey)}B")
    print(f"verify over full M .............. {full}")
    print(f"verify over artifact_hash only .. {only}  (must be False)")
    print(f"verify over 1-bit-flipped M ..... {mut}  (must be False)")
    ok = full and not only and not mut
    print("\n" + ("CONFIRMED: the on-chain Falcon-1024 signature verifies offline over the 102B "
                  "_build_message preimage." if ok else "MISMATCH — investigate."))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
