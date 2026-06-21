#!/usr/bin/env bash
# One-shot verification of the whole suite. Offline tests + a live on-chain conformance check.
set -e
cd "$(dirname "$0")"

echo "== python core unit =="
python test_falcon_interop.py

echo "== KAT conformance validation =="
python falcon_interop.py kat kat/falcon1024_det.onchain.json >/dev/null && echo "  onchain.json OK"
python falcon_interop.py kat kat/falcon1024_det.example.json >/dev/null && echo "  example.json OK"

echo "== SDK unit (offline) =="
PQC_SKIP_LIVE=1 node packages/verify-pqc/test.js

echo "== anchor commitment round-trip =="
python anchor/anchor_sth.py verify anchor/anchor-demo.json | grep -i "matches"

echo "== LIVE on-chain conformance (app 763809096) =="
node tools/conformance-check.js 763809096 | tail -1

echo ""
echo "ALL SUITE TESTS PASS"
