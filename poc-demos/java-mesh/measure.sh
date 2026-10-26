#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Measures Paztport's verification overhead and header sizes against the running
# stack, and prints the numbers reported in the README (§12).
#
#   PA_ADMIN_TOKEN=<token> docker compose up -d --build   # stack must be running first
#   PA_ADMIN_TOKEN=<token> ./measure.sh   # same token, for /admin/mode
#
# It runs the k6 load twice — payment in `off` mode (no verification) and
# `enforce` mode — so the difference is the verifier's cost. Then it reads one
# real captured request to report on-the-wire header sizes.

set -u
cd "$(dirname "$0")"

: "${PA_ADMIN_TOKEN:?set PA_ADMIN_TOKEN to the token payment was started with}"

MESH="paztport-mesh"
CURL="curlimages/curl:latest"
VUS="${VUS:-10}"
DURATION="${DURATION:-20s}"

mc() { docker run --rm --network "$MESH" "$CURL" -s "$@"; }

set_mode() { # $1 = off|enforce ; exits unless payment accepts the switch
  local code
  code=$(mc -o /dev/null -w '%{http_code}' -X POST "http://payment:8080/admin/mode?value=$1" \
    -H "X-Admin-Token: $PA_ADMIN_TOKEN")
  if [ "$code" != "200" ]; then
    echo "measure.sh: switching payment to $1 failed (HTTP $code); is PA_ADMIN_TOKEN the token payment was started with?" >&2
    exit 1
  fi
}

run_load() { # echoes the RESULT line for the current mode
  for _ in $(seq 1 20); do
    mc -o /dev/null -X POST http://gateway:8080/checkout -H 'Content-Type: application/json' -d '{}'
  done
  docker run --rm --network "$MESH" \
    -e TARGET=http://gateway:8080/checkout -e VUS="$VUS" -e DURATION="$DURATION" \
    -v "$PWD/load.js:/scripts/load.js:ro" grafana/k6 run /scripts/load.js 2>/dev/null | grep RESULT
}

echo "== latency: payment off vs enforce (VUS=$VUS DURATION=$DURATION) =="
set_mode off
echo "off     $(run_load)"
set_mode enforce
echo "enforce $(run_load)"

echo ""
echo "== header sizes from one real request =="
mc -X POST http://gateway:8080/checkout -H 'Content-Type: application/json' -d '{}' >/dev/null
CAP=$(mc http://payment:8080/debug/last-request)
printf '%s' "$CAP" | python3 -c '
import sys, json
c = json.load(sys.stdin)
chain, proof = c["chain"], c["proof"]
raw = json.loads(__import__("base64").urlsafe_b64decode(chain + "=="* (-len(chain)%4)))
print(f"chain depth (stamps): {len(raw)}")
print(f"X-Path-Chain bytes:   {len(chain)}  (~{len(chain)//len(raw)} per stamp)")
print(f"X-Path-Proof bytes:   {len(proof)}  (fixed, depth-8 padded)")
print(f"total header bytes:   {len(chain)+len(proof)}")
'

# restore enforce
set_mode enforce
echo ""
echo "(payment restored to enforce)"
