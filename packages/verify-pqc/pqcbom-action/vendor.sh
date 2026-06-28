#!/usr/bin/env bash
# Re-vendor the zero-dep scanner into the action (run from packages/verify-pqc/). Keep byte-identical.
cp pqcbom.mjs pqcbom-action/pqcbom.mjs && echo "synced pqcbom.mjs -> pqcbom-action/"
