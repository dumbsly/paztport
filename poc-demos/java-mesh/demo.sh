#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Paztport demo: runs every scenario and prints a pass/fail table.
#
# Prerequisites (see README):
#   (cd ../../poc-sdks/java && mvn -q install -DskipTests)
#   mvn -q package -DskipTests
#
# This script is idempotent. On each run it regenerates keys if missing,
# restores the original policy and rebuilds the root, (re)starts the mesh, and
# resets payment to enforce mode. All calls go over the mesh network via a
# throwaway curl container, so only the gateway port need ever be exposed.

set -u
cd "$(dirname "$0")"

MESH="paztport-mesh"
CURL="curlimages/curl:latest"

# Faster ESCALATE: the circuit breaker trips on the 2nd quarantine instead of the 3rd.
export QUARANTINE_MAX_PER_SVC=1

pass=0
fail=0
RESULTS=""

record() { # status name detail
  if [ "$1" = "PASS" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  RESULTS+=$(printf '\n  %-4s | %-58s | %s' "$1" "$2" "$3")
}

# mreq METHOD URL [curl args...] -> sets CODE and BODY
mreq() {
  local method="$1" url="$2"
  shift 2
  local out
  out=$(docker run --rm --network "$MESH" "$CURL" -s -w $'\n%{http_code}' -X "$method" "$url" "$@" 2>/dev/null)
  CODE=$(printf '%s' "$out" | tail -n1)
  BODY=$(printf '%s' "$out" | sed '$d')
}

check_code() { # name expected_code
  if [ "$CODE" = "$2" ]; then record PASS "$1" "HTTP $CODE"; else record FAIL "$1" "expected HTTP $2, got $CODE ($BODY)"; fi
}

check_reason() { # name expected_code expected_reason
  if [ "$CODE" = "$2" ] && printf '%s' "$BODY" | grep -q "$3"; then
    record PASS "$1" "HTTP $CODE $3"
  else
    record FAIL "$1" "expected HTTP $2/$3, got $CODE ($BODY)"
  fi
}

write_paths() { # writes policy/paths.yaml with the given extra route flag
  {
    echo "paths:"
    echo "  - [gateway, orders, payment]"
    echo "  - [gateway, orders]"
    echo "  - [gateway, search]"
    [ "${1:-}" = "widen" ] && echo "  - [gateway, search, payment]"
  } > policy/paths.yaml
}

rebuild_policy() { # rebuilds root + bundles; all proof/root holders must reload together
  # Each policy-tool run uses fresh salts, so the root bytes change; every service
  # that pins a root or holds proofs must recreate to reload the files (and to rejoin
  # the mesh if a prior run left it quarantined).
  docker compose run --rm policy-tool >/dev/null 2>&1
  docker compose up -d --force-recreate gateway orders payment search >/dev/null 2>&1
  wait_ready
}

remove_replacements() { # drop any responder-created replacement containers
  ids=$(docker ps -aq --filter "label=paztport.replacement=true")
  [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1
  return 0
}

wait_ready() {
  for svc in gateway search payment; do
    for _ in $(seq 1 30); do
      mreq GET "http://$svc:8080/__ping" 2>/dev/null
      [ "$CODE" != "000" ] && [ -n "$CODE" ] && break
      sleep 1
    done
  done
}

echo "== Paztport demo =="
echo "bringing up the mesh..."
[ -f out/keys/keyring.json ] || docker compose run --rm keygen >/dev/null 2>&1
remove_replacements                          # clear any stray replacements from a prior run
PAZTPORT_ADMIN_TOKEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')   # per-run token for /admin/mode
export PAZTPORT_ADMIN_TOKEN
# The policy files must exist before the first `up`: Docker creates a missing bind-mount
# source as an empty directory, which the services then fail to read and the policy-tool
# cannot overwrite. So write the policy and build the root before starting the mesh.
for p in out/policy/*; do [ -d "$p" ] && rmdir "$p" 2>/dev/null; done   # leftovers from such a run
write_paths            # restore original policy
docker compose run --rm policy-tool >/dev/null 2>&1
RESPONDER_URL="" docker compose up -d --build --force-recreate >/dev/null 2>&1  # fresh mesh, payment log-only
rebuild_policy         # rebuild original root, recreate services (resets mode=enforce)

echo "running scenarios..."

# 1 — legitimate end to end
mreq POST "http://gateway:8080/checkout" -H 'Content-Type: application/json' -d '{}'
check_code "1  legit gateway->orders->payment" 200

# 2 — no headers
mreq POST "http://search:8080/attack/no-headers"
check_reason "2  no headers" 403 CHAIN_MISSING

# 3 — forged gateway stamp, search's key
mreq POST "http://search:8080/attack/forge-gateway"
check_reason "3  forged gateway stamp" 403 BAD_SIGNATURE

# 4 — forward a real gateway->search chain to payment (no proof exists)
mreq GET "http://gateway:8080/find"
mreq POST "http://search:8080/attack/forward-stolen"
check_reason "4  forward stolen chain" 403 PATH_NOT_ALLOWED

# 5 — replay a captured valid request
mreq POST "http://gateway:8080/checkout" -H 'Content-Type: application/json' -d '{}'
mreq POST "http://search:8080/attack/replay"
check_reason "5  replay" 403 REPLAY

# 6 — valid chain, body altered after the last stamp
mreq POST "http://gateway:8080/checkout" -H 'Content-Type: application/json' -d '{}'
mreq POST "http://search:8080/attack/alter-body"
check_reason "6  body altered" 403 BINDING_MISMATCH

# 7 — chain older than max age
mreq POST "http://gateway:8080/checkout" -H 'Content-Type: application/json' -d '{}'
echo "   (scenario 7: waiting out the 5s max age...)"
sleep 6
mreq POST "http://search:8080/attack/replay"
check_reason "7  expired" 403 EXPIRED

# 8 — scenarios 2-4 in audit mode: all pass, events logged, no quarantine
mreq POST "http://payment:8080/admin/mode?value=audit" -H "X-Admin-Token: $PAZTPORT_ADMIN_TOKEN"
mreq POST "http://search:8080/attack/no-headers";    check_code "8a audit: no headers" 200
mreq POST "http://search:8080/attack/forge-gateway";  check_code "8b audit: forged stamp" 200
mreq GET  "http://gateway:8080/find"
mreq POST "http://search:8080/attack/forward-stolen"; check_code "8c audit: forward stolen" 200
if docker compose logs payment 2>/dev/null | grep -q "PAZTPORT_EVENT.*audit=true"; then
  record PASS "8d audit: events logged" "found PAZTPORT_EVENT audit=true"
else
  record FAIL "8d audit: events logged" "no audit events in payment logs"
fi
mreq POST "http://payment:8080/admin/mode?value=enforce" -H "X-Admin-Token: $PAZTPORT_ADMIN_TOKEN"

# 10 — widen policy so gateway->search->payment is allowed; scenario 4 now passes
write_paths widen
rebuild_policy
mreq GET "http://gateway:8080/find"
mreq POST "http://search:8080/attack/forward-stolen"
check_reason "10 policy widened -> forward allowed" 200 PAID

# restore original policy before the responder scenarios
write_paths
rebuild_policy

# 9 — three illicit calls quarantine search; a clean replacement takes over.
# The responder is only enabled here, so scenarios 1-8/10 don't pollute its counts.
echo "   (scenario 9: enabling responder, driving quarantine — this is the slow one...)"
export RESPONDER_URL=http://responder:8080
docker compose up -d --force-recreate payment responder >/dev/null 2>&1
wait_ready
OLD_SEARCH=$(docker compose ps -q search)

for _ in 1 2 3; do
  mreq GET  "http://gateway:8080/find"
  mreq POST "http://search:8080/attack/forward-stolen"
done

isolated=false
for _ in $(seq 1 40); do
  nets=$(docker inspect -f '{{json .NetworkSettings.Networks}}' "$OLD_SEARCH" 2>/dev/null)
  if echo "$nets" | grep -q quarantine && ! echo "$nets" | grep -q "$MESH"; then isolated=true; break; fi
  sleep 1
done

served=false
for _ in $(seq 1 40); do
  mreq GET "http://gateway:8080/find"
  [ "$CODE" = "200" ] && { served=true; break; }
  sleep 1
done

if $isolated && $served; then
  record PASS "9  quarantine + replacement" "suspect isolated on quarantine net, replacement serves gateway->search"
else
  record FAIL "9  quarantine + replacement" "isolated=$isolated served=$served (last /find HTTP $CODE)"
fi

# ESCALATE — a further quarantine for the same service exceeds the per-service limit.
for _ in 1 2 3; do
  mreq GET  "http://gateway:8080/find"
  mreq POST "http://search:8080/attack/forward-stolen"
done
sleep 3
if docker compose logs responder 2>/dev/null | grep -q "ESCALATE svc=search"; then
  record PASS "9b ESCALATE past circuit breaker" "responder logged ESCALATE svc=search"
else
  record FAIL "9b ESCALATE past circuit breaker" "no ESCALATE in responder logs"
fi

# clean up: drop replacements, restore the mesh and policy, responder off
remove_replacements
export RESPONDER_URL=""
docker compose up -d --force-recreate >/dev/null 2>&1
write_paths

echo ""
echo "== results =="
printf '%s\n' "$RESULTS"
echo ""
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
