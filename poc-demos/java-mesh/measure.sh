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
# It waits up to READY_WAIT seconds (90, a whole number) for the stack to answer a
# checkout, so it can run straight after `docker compose up`. The curl and k6 images
# are pulled first if they are not here yet, so a first pull does not use up the wait.
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
# Each image pinned by the digest of its index: curl 8.23.0, as the Envoy Gateway checks run it, and k6 2.3.0
# (released 2026-09-21).
CURL="docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"
K6="docker.io/grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8"
VUS="${VUS:-10}"
DURATION="${DURATION:-20s}"
WARMUP="${WARMUP:-10s}"
ROUNDS="${ROUNDS:-3}"
READY_WAIT="${READY_WAIT:-90}"
# The wait's deadline is shell arithmetic: text that is not a number ends the script with a bare shell error
# (unbound variable, invalid operator, value too great for base), and an empty or negative value gives up at once.
case "$READY_WAIT" in
  '' | *[!0-9]*)
    echo "measure.sh: READY_WAIT must be a whole number of seconds (got '$READY_WAIT')" >&2
    exit 2
    ;;
esac
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

wait_ready() { # exits unless one checkout gets a 200 through gateway, orders and payment within READY_WAIT seconds
  # `docker compose up -d` returns once the containers run, before the JVMs listen, and the services have no
  # health check of their own: the legitimate path answering 200 is the one sign every hop is up.
  # 10# reads READY_WAIT as base 10, so 08 is not taken as octal
  local code="" end=$(($(date +%s) + 10#$READY_WAIT))
  while [ "$(date +%s)" -lt "$end" ]; do
    code=$(mc --max-time 5 -o /dev/null -w '%{http_code}' -X POST https://gateway:8080/checkout \
      -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  # No code at all means docker could not start the probe, as when the stack's network does not exist.
  echo "measure.sh: the stack did not answer a checkout with 200 within ${READY_WAIT}s (last: ${code:-no answer});" \
    "is it up (docker compose ps), and does a checkout succeed (docker compose logs gateway orders payment)?" >&2
  exit 1
}

run_load() { # $1 = duration; echoes the run's RESULT line
  # k6 gets only the operator's certificate and key: it cannot be given a CA (see load.js).
  docker run --rm --user 0:0 --network "$MESH" "${OPERATOR[@]}" \
    -e TARGET=https://gateway:8080/checkout -e VUS="$VUS" -e DURATION="$1" \
    -v "$PWD/load.js:/scripts/load.js:ro" "$K6" run /scripts/load.js 2>/dev/null | grep RESULT
}

# Present before the wait's timer starts, so a first pull is not counted in READY_WAIT.
for image in "$CURL" "$K6"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || {
    echo "measure.sh: could not pull $image; is the registry reachable?" >&2
    exit 1
  }
done

wait_ready
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
