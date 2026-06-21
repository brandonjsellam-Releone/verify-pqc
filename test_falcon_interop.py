"""Unit tests for the falcon_interop conformance core. Run: python test_falcon_interop.py"""
import os
import sys
import falcon_interop as F

_p = [0, 0]
def ok(cond, msg):
    if cond: _p[0] += 1
    else: _p[1] += 1; print("FAIL:", msg)

# inspect: 0xBA deterministic compressed (no salt)
det = bytes([0xBA]) + b"\x11" * 1200
i = F.inspect(det)
ok(i.header_hex == "0xba" and i.deterministic and i.fmt == "compressed"
   and i.logn == 10 and not i.salt_present and i.total_len == 1201, "inspect 0xBA")

# inspect: 0x3A randomized compressed (salt present)
rnd = bytes([0x3A]) + b"\x22" * 40 + b"\x11" * 1200
j = F.inspect(rnd)
ok((not j.deterministic) and j.salt_present and j.body_len == 1200, "inspect 0x3A salt")

# abi_decode_bytes: strips 2-byte BE prefix when it equals len-2
abi = bytes([0x04, 0xd4]) + bytes([0xBA]) + b"\x00" * 1235
dec = F.abi_decode_bytes(abi)
ok(len(dec) == 1236 and dec[0] == 0xBA, "abi_decode strips prefix")

# abi_decode_bytes: no-op when prefix != len-2
noabi = bytes([0xBA]) + b"\x00" * 100
ok(len(F.abi_decode_bytes(noabi)) == 101 and F.abi_decode_bytes(noabi)[0] == 0xBA, "abi_decode no-op")

# compare: identical deterministic vectors
ok(F.compare(det, det).identical, "compare identical")

# compare: localizes header divergence
c = F.compare(det, rnd)
ok((not c.identical) and c.diff_region == "header", "compare header region")

# compare: localizes body divergence at the right offset
det2 = bytes([0xBA]) + b"\x11" * 1199 + b"\x99"
d = F.compare(det, det2)
ok((not d.identical) and d.diff_region == "body" and d.first_diff_offset == 1200, "compare body region")

# load_kat: the real on-chain golden vector validates (1236 B, 0xBA)
here = os.path.dirname(os.path.abspath(__file__))
v = F.load_kat(os.path.join(here, "kat", "falcon1024_det.onchain.json"))["_validation"]
ok(v["ok"] and v["inspected"]["header_hex"] == "0xba" and v["inspected"]["total_len"] == 1236,
   "load_kat onchain")

# variable-length: the template vector is a DIFFERENT length and still valid
v2 = F.load_kat(os.path.join(here, "kat", "falcon1024_det.example.json"))["_validation"]
ok(v2["ok"] and v2["inspected"]["total_len"] != 1236, "load_kat variable-length")

# no KAT field implies FN-DSA (hard constraint)
import json
for name in ("falcon1024_det.onchain.json", "falcon1024_det.example.json"):
    raw = open(os.path.join(here, "kat", name), encoding="utf-8").read()
    bare = ("FN-DSA" in raw) and ("NOT FIPS-206 / FN-DSA" not in raw.replace(name, ""))
    # allow the explicit disclaimer phrasing only
    ok("FN-DSA" not in raw or "NOT FIPS-206 / FN-DSA" in raw, "no bare FN-DSA in " + name)

print("falcon_interop:", _p[0], "pass,", _p[1], "fail")
sys.exit(0 if _p[1] == 0 else 1)
