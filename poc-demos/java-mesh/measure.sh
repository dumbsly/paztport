#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Measures what Paztport costs on payment, and the header sizes, against the
# running stack, and prints the numbers reported under Measurements in this
# demo's README.
#
#   PAZTPORT_ADMIN_TOKEN=<token> docker compose up -d --build   # stack must be running first
#   PAZTPORT_ADMIN_TOKEN=<token> ./measure.sh   # same token, for /admin/mode
#
# It drives the legitimate path with k6, with payment in `off` mode (Paztport off
# on that hop) and in `enforce` mode. The difference between the two covers
# payment's request verification, payment's signing of its response, and orders'
# check of that response stamp, which in `off` finds no stamp and stops at once.
# Everything else is in both runs and so cancels out: mutual TLS on every hop, the
# request stamps gateway and orders sign, orders' verification of the chain it
# receives from gateway (it doesn't enforce, but runs the full live order to
# decide its own attestation), orders' response stamp and gateway's check of it.
# Neither those costs nor mutual TLS are isolated here.
#
# Method: first a discarded warm-up in each mode (WARMUP each), so neither mode
# pays the JVMs' and the connections' warm-up; then ROUNDS rounds of one run per
# mode (DURATION each), the leading mode alternating from round to round (off
# then enforce, enforce then off, ...), so drift over time does not favour one
# mode. Every run's RESULT line is printed, then each mode's median, over its
# runs, of the runs' p50 and p99.

set -u
cd "$(dirname "$0")"

: "${PAZTPORT_ADMIN_TOKEN:?set PAZTPORT_ADMIN_TOKEN to the token payment was started with}"

MESH="paztport-mesh"
CURL="curlimages/curl:latest"
VUS="${VUS:-10}"
DURATION="${DURATION:-20s}"
WARMUP="${WARMUP:-10s}"
ROUNDS="${ROUNDS:-3}"
# Every hop is mutual TLS, so the curl and k6 containers present the operator's
# certificate, mounted file by file. The key files are owner-only and both images
# run as an unprivileged user, so the containers run as root to read them.
CA=(-v "$PWD/out/keys/tls/ca.crt:/tls/ca.crt:ro")
OPERATOR=(-v "$PWD/out/keys/tls/operator.crt:/tls/operator.crt:ro"
  -v "$PWD/out/keys/tls/operator.key:/tls/operator.key:ro")

mc() {
  docker run --rm --user 0:0 --network "$MESH" "${CA[@]}" "${OPERATOR[@]}" "$CURL" -s \
    --cacert /tls/ca.crt --cert /tls/operator.crt --key /tls/operator.key "$@"
}

set_mode() { # $1 = off|enforce ; exits unless payment accepts the switch
  local code
  code=$(mc -o /dev/null -w '%{http_code}' -X POST "https://payment:8080/admin/mode?value=$1" \
    -H "X-Admin-Token: $PAZTPORT_ADMIN_TOKEN")
  if [ "$code" != "200" ]; then
    echo "measure.sh: switching payment to $1 failed (HTTP $code); is PAZTPORT_ADMIN_TOKEN the token payment was started with?" >&2
    exit 1
  fi
}

run_load() { # $1 = duration; echoes the run's RESULT line
  # k6 gets only the operator's certificate and key: it cannot be given a CA (see load.js).
  docker run --rm --user 0:0 --network "$MESH" "${OPERATOR[@]}" \
    -e TARGET=https://gateway:8080/checkout -e VUS="$VUS" -e DURATION="$1" \
    -v "$PWD/load.js:/scripts/load.js:ro" grafana/k6 run /scripts/load.js 2>/dev/null | grep RESULT
}

echo "== latency: payment off vs enforce (VUS=$VUS DURATION=$DURATION WARMUP=$WARMUP ROUNDS=$ROUNDS) =="
for mode in off enforce; do
  set_mode "$mode"
  echo "warm-up $mode (discarded): $(run_load "$WARMUP")"
done
RUNS=""
for round in $(seq 1 "$ROUNDS"); do
  if [ $((round % 2)) -eq 1 ]; then order="off enforce"; else order="enforce off"; fi
  for mode in $order; do
    set_mode "$mode"
    line="$(run_load "$DURATION")"
    printf '%-7s %s\n' "$mode" "$line"
    RUNS+="$mode $line"$'\n'
  done
done
printf '%s' "$RUNS" | python3 -c '
import re, statistics, sys
runs = {}
for line in sys.stdin:
    mode, _, rest = line.partition(" ")
    m = re.search(r"med=([0-9.]+)ms p99=([0-9.]+)ms .* fail=([0-9.]+)%", rest)
    if not m:
        sys.exit(f"measure.sh: no RESULT line for a {mode} run")
    runs.setdefault(mode, []).append(tuple(float(v) for v in m.groups()))
for mode in ("off", "enforce"):
    r = runs[mode]
    print(f"median of {len(r)} {mode} runs: p50={statistics.median(x[0] for x in r):.2f}ms "
          f"p99={statistics.median(x[1] for x in r):.2f}ms worst fail={max(x[2] for x in r):.2f}%")
' || exit 1

echo ""
echo "== header sizes from one real request =="
mc -X POST https://gateway:8080/checkout -H 'Content-Type: application/json' -d '{}' >/dev/null
CAP=$(mc https://payment:8080/debug/last-request)
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
