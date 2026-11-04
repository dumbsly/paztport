#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The Envoy Gateway proof of concept on a local kind cluster.
#
#   ./run envoy-gateway          builds the jars and the keys, then runs up and check
#   envoy-gateway.sh up          makes the cluster: Envoy Gateway, the Gateway, orders and payment, and the chart
#   envoy-gateway.sh check       runs the checks against it and prints a pass/fail table
#   envoy-gateway.sh down        deletes the cluster
#
# up needs the jars built and out/ made (material.sh). It builds the images locally and loads them into kind;
# nothing is pushed anywhere. It refuses to run while the cluster exists, and leaves it running for inspection.
# Every kubectl and helm call names the cluster's own context, so no other cluster is touched.
set -u
cd "$(dirname "$0")"
here="$PWD"
repo="$(cd ../.. && pwd)"
# How the hints name this script: by the path from the repository's root, where ./run is.
self="poc-demos/envoy-gateway/envoy-gateway.sh"

CLUSTER=paztport-envoy-gateway
CTX="kind-$CLUSTER"
NS=paztport
EG_NS=envoy-gateway-system
EG_CHART=oci://docker.io/envoyproxy/gateway-helm
EG_VERSION=v1.9.2
EG_IMAGE=docker.io/envoyproxy/gateway:v1.9.2@sha256:9d67017c442a70e6ae9f1a358e6c80eb653c67c2e40823d9a991e0daf37ba926
KEYS="$here/out/keys"
POLICY="$here/out/policy"
# The edge: Envoy's Service, which the EnvoyProxy names, on the Gateway's listener port.
EDGE="http://paztport-edge.$EG_NS.svc"

k() { kubectl --context "$CTX" "$@"; }
kn() { kubectl --context "$CTX" -n "$NS" "$@"; }

quietly() { # what command... : runs a setup step with its output hidden, but stops if it fails
  local what="$1"
  shift
  local out status
  out=$("$@" 2>&1)
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'error: %s failed (exit status %s). Its last output:\n' "$what" "$status" >&2
    printf '%s\n' "$out" | tail -n 30 >&2
    exit 1
  fi
}

cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER"
}

# apply_files <namespace> configmap|secret <name> <key=path>...: makes or replaces a ConfigMap or Secret from files.
apply_files() {
  local ns="$1" kind="$2" name="$3"
  shift 3
  local args=()
  for kv in "$@"; do args+=(--from-file="$kv"); done
  [ "$kind" = configmap ] || kind="secret generic"
  # shellcheck disable=SC2086 # "secret generic" is two words
  k -n "$ns" create $kind "$name" "${args[@]}" --dry-run=client -o yaml | k apply -f -
}

apply_tls() { # <namespace> <name> <certificate> <key>
  k -n "$1" create secret tls "$2" --cert="$3" --key="$4" --dry-run=client -o yaml | k apply -f -
}

build_images() {
  docker build -q -f "$repo/poc-demos/envoy-gateway/processor/Dockerfile" -t paztport-processor:dev "$repo" &&
    for svc in orders payment; do
      docker build -q -f "$repo/poc-demos/java-mesh/Dockerfile" \
        --build-arg JAR="poc-demos/java-mesh/services/$svc/target/$svc.jar" -t "paztport-$svc:dev" "$repo" || return 1
    done
}

load_images() {
  for image in paztport-processor:dev paztport-orders:dev paztport-payment:dev; do
    kind load docker-image --name "$CLUSTER" "$image" || return 1
  done
}

# The files each part is given, from out/: never the CA's key, and each service only its own keys.
make_material() {
  apply_tls "$EG_NS" edge-client-tls "$KEYS/tls/edge.crt" "$KEYS/tls/edge.key" &&
    apply_files "$NS" configmap mesh-ca "ca.crt=$KEYS/tls/ca.crt" &&
    apply_files "$NS" configmap mesh-policy "keyring.json=$KEYS/keyring.json" "policy.pub=$KEYS/policy.pub" \
      "root.json=$POLICY/root.json" "proofs-orders.json=$POLICY/proofs-orders.json" &&
    apply_files "$NS" secret orders-key "orders.key=$KEYS/orders.key" &&
    apply_files "$NS" secret payment-key "payment.key=$KEYS/payment.key" &&
    apply_files "$NS" secret edge-key "edge.key=$KEYS/edge.key" &&
    apply_tls "$NS" orders-tls "$KEYS/tls/orders.crt" "$KEYS/tls/orders.key" &&
    apply_tls "$NS" payment-tls "$KEYS/tls/payment.crt" "$KEYS/tls/payment.key" &&
    apply_tls "$NS" paztport-processor-tls "$KEYS/tls/paztport-processor.crt" "$KEYS/tls/paztport-processor.key" &&
    apply_tls "$NS" operator-tls "$KEYS/tls/operator.crt" "$KEYS/tls/operator.key"
}

# install_chart [helm args...]: installs or upgrades the processor's chart, the edge's key, the processor's TLS and
# the mesh CA named as the Secrets and ConfigMap above, the public material passed as files.
install_chart() {
  helm --kube-context "$CTX" upgrade --install paztport "$here/chart" -n "$NS" \
    --set material.existingKeySecret=edge-key \
    --set tls.existingSecret=paztport-processor-tls \
    --set tls.existingCAConfigMap=mesh-ca \
    --set-file material.pin="$KEYS/policy.pub" \
    --set-file 'material.keyrings[0]'="$KEYS/keyring.json" \
    --set-file 'material.roots[0]'="$POLICY/root.json" \
    --set-file material.bundle="$POLICY/proofs-edge.json" \
    --set 'extraRoutes={orders-unmapped}' \
    "$@"
}

# wait_edge: until the Gateway is programmed, its Envoy is available, and orders, payment, the processor and the pod
# checks are ready.
wait_edge() {
  k -n "$NS" wait --for=condition=Programmed gateway/edge --timeout=180s &&
    k -n "$EG_NS" wait --for=condition=Available deployment \
      -l "gateway.envoyproxy.io/owning-gateway-name=edge,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
      --timeout=180s &&
    for d in orders payment paztport-processor; do
      k -n "$NS" rollout status "deployment/$d" --timeout=300s || return 1
    done &&
    k -n "$NS" wait --for=condition=Ready pod/checks --timeout=120s
}

cmd_up() {
  if cluster_exists; then
    echo "the cluster $CLUSTER is up already; check it with $self check, or remove it with $self down" >&2
    exit 1
  fi
  [ -d "$KEYS" ] && [ -d "$POLICY" ] || { echo "no keys in $here/out: run material.sh first" >&2; exit 1; }
  echo "== building the images (processor, orders, payment)"
  quietly "building the images" build_images
  echo "== making the kind cluster $CLUSTER"
  quietly "making the cluster" kind create cluster --config kind/cluster.yaml
  quietly "loading the images into kind" load_images
  echo "== installing Envoy Gateway $EG_VERSION"
  quietly "installing Envoy Gateway" helm --kube-context "$CTX" install eg "$EG_CHART" --version "$EG_VERSION" \
    -n "$EG_NS" --create-namespace --set global.images.envoyGateway.image="$EG_IMAGE" --wait --timeout 5m
  echo "== the Gateway, orders and payment, and the processor's chart"
  quietly "making the namespace" k create namespace "$NS"
  quietly "loading the keys and the policy" make_material
  quietly "applying the Gateway" k apply -f kind/gateway.yaml
  quietly "applying the backends" k apply -f kind/backends.yaml -f kind/checks.yaml
  quietly "installing the chart" install_chart --wait --timeout 5m
  quietly "waiting for the edge" wait_edge
  echo ""
  echo "up: the cluster $CLUSTER is running (kubectl context $CTX)."
  echo "  check it:  $self check"
  echo "  remove it: $self down"
}

cmd_down() {
  if ! cluster_exists; then
    echo "no cluster $CLUSTER to remove"
    return 0
  fi
  quietly "deleting the cluster" kind delete cluster --name "$CLUSTER"
  echo "down: the cluster $CLUSTER is deleted"
}

# --- the checks ---
#
# Each request a check makes goes from the pod `checks` (curl, with the operator's and payment's certificates) or,
# for the two requests curl cannot make, from edgecheck on this machine through kubectl port-forward. Each check
# prints what it saw; the table at the end is sorted by check.

pass=0
fail=0
ROWS=""

record() { # status name detail
  if [ "$1" = "PASS" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  ROWS+=$(printf '\n  %-4s | %-60s | %s' "$1" "$2" "$3")
}

# edge_req <path> [curl args...]: a request through the Gateway from the pod checks -> CODE, HEADERS, BODY
edge_req() {
  local path="$1"
  shift
  pod_curl "$EDGE$path" "$@"
}

# mesh_req <cert> <url> [curl args...]: a request straight to a mesh service, over mutual TLS with the pod's
# certificate <cert> (operator or payment) -> CODE, HEADERS, BODY
mesh_req() {
  local cert="$1" url="$2"
  shift 2
  pod_curl "$url" --cacert /tls/ca.crt --cert "/tls/$cert.crt" --key "/tls/$cert.key" "$@"
}

pod_curl() { # <url> [curl args...] -> CODE, HEADERS, BODY
  local url="$1" out
  shift
  out=$(kn exec checks -- curl -s -i -w $'\n%{http_code}' "$@" "$url" 2>/dev/null)
  CODE=$(printf '%s' "$out" | tail -n1)
  out=$(printf '%s' "$out" | sed '$d' | tr -d '\r')
  HEADERS=$(printf '%s\n' "$out" | sed '/^$/q')
  BODY=$(printf '%s\n' "$out" | sed '1,/^$/d')
}

# Logs. Each snapshot is every line so far; added <before> <now> prints the lines in now that before lacks.
processor_log() { kn logs -l app.kubernetes.io/name=paztport-processor --tail=-1 --prefix 2>/dev/null; }
traces() { kn logs -l "app=$1" --tail=-1 --prefix 2>/dev/null | grep -F 'PAZTPORT_TRACE request'; }
events() { kn logs -l "app=$1" --tail=-1 --prefix 2>/dev/null | grep -F 'PAZTPORT_EVENT'; }
added() {
  if [ -z "$1" ]; then printf '%s\n' "$2"; else grep -vxF -f <(printf '%s\n' "$1") <<<"$2"; fi
}

# await <var> <pattern> <command...>: runs command until its output has a line matching the extended regular
# expression pattern (logs reach kubectl a moment late), for up to 10 s; sets var to that line, or empty.
await() {
  local var="$1" pattern="$2" line=""
  shift 2
  for _ in $(seq 1 20); do
    line=$("$@" | grep -E -- "$pattern" | tail -n1)
    [ -n "$line" ] && break
    sleep 0.5
  done
  printf -v "$var" '%s' "$line"
}

# forward <namespace> <service> <port>: kubectl port-forward to the service in the background -> FORWARDED (the
# local address). The forward bypasses the NetworkPolicy, as kubectl's own traffic does; the checks use it only
# where that is the point: to reach the processor with a certificate, and to make a request curl cannot.
forward() {
  local log="$tmp/forward-$2.log" addr=""
  k -n "$1" port-forward "svc/$2" ":$3" >"$log" 2>&1 &
  forwards+=("$!")
  disown "$!"
  for _ in $(seq 1 40); do
    addr=$(sed -n 's/^Forwarding from \(127\.0\.0\.1:[0-9]*\) .*/\1/p' "$log" | head -n1)
    [ -n "$addr" ] && break
    sleep 0.25
  done
  [ -n "$addr" ] || { echo "error: no port-forward to $2: $(cat "$log")" >&2; exit 1; }
  FORWARDED="$addr"
}

# chain_rid <chain>: the rid of the first stamp in an X-Path-Chain value (base64url JSON).
chain_rid() {
  local s
  s=$(printf '%s' "$1" | tr '_-' '/+')
  while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done
  printf '%s' "$s" | base64 -d 2>/dev/null | sed -n 's/.*"rid":"\([A-Za-z0-9-]*\)".*/\1/p'
}

# metric_sum <text> <string>...: the sum of the samples in the metrics text whose line holds every string given.
metric_sum() {
  local text="$1"
  shift
  for p in "$@"; do text=$(printf '%s\n' "$text" | grep -F -- "$p"); done
  printf '%s\n' "$text" | awk 'NF { s += $NF } END { printf "%d", s }'
}

cmd_check() {
  cluster_exists || { echo "no cluster $CLUSTER: run $self up first" >&2; exit 1; }
  tmp="$(mktemp -d)"
  forwards=()
  trap 'kill "${forwards[@]}" 2>/dev/null; rm -rf "$tmp"' EXIT
  quietly "building edgecheck" bash -c "cd '$here/processor' && go build -o '$tmp/edgecheck' ./cmd/edgecheck"
  forward "$NS" paztport-processor 9002
  processor_addr="$FORWARDED"
  forward "$EG_NS" paztport-edge 80
  edge_addr="$FORWARDED"
  local pod_ip
  pod_ip=$(kn get pod checks -o jsonpath='{.status.podIP}')

  echo "== checking the edge"

  # 1 - a request through the Gateway is stamped by the edge, and verified at orders and then at payment.
  local p0 o0 y0 stamped rid ord pay detail
  p0=$(processor_log); o0=$(traces orders); y0=$(traces payment)
  edge_req /orders -X POST -H 'content-type: application/json' -d '{}'
  local check1_headers="$HEADERS"
  await stamped '"outcome":"stamped"' added "$p0" "$(processor_log)"
  rid=$(printf '%s' "$stamped" | sed -n 's/.*"rid":"\([^"]*\)".*/\1/p')
  await ord "rid=${rid:-none} reason=OK receiver=orders ✓ peer=edge \(mTLS\)" added "$o0" "$(traces orders)"
  await pay "rid=${rid:-none} reason=OK receiver=payment ✓ peer=orders \(mTLS\)" added "$y0" "$(traces payment)"
  if [ "$CODE" = 200 ] && [ -n "$rid" ] && [ -n "$ord" ] && [ -n "$pay" ]; then
    record PASS "1  via the Gateway: stamped, verified at orders and payment" \
      "HTTP 200; rid $rid: orders reason=OK peer=edge (mTLS), payment reason=OK peer=orders (mTLS)"
  else
    detail="expected HTTP 200 and both traces OK, got HTTP $CODE, rid '${rid}', orders [${ord:-no line}]"
    record FAIL "1  via the Gateway: stamped, verified at orders and payment" "$detail, payment [${pay:-no line}]"
  fi

  # 2 - a request straight to orders, with no chain, is refused there.
  mesh_req operator https://orders:8080/orders -X POST -H 'content-type: application/json' -d '{}'
  if [ "$CODE" = 403 ] && printf '%s' "$BODY" | grep -q CHAIN_MISSING; then
    record PASS "2  straight to orders, no chain: refused" "HTTP 403 CHAIN_MISSING"
  else
    record FAIL "2  straight to orders, no chain: refused" "expected HTTP 403 CHAIN_MISSING, got $CODE ($BODY)"
  fi

  # 7 - a stamp taken from the processor (as Envoy, with the edge's certificate), sent to orders from a pod holding
  # payment's certificate: the peer is not the stamp's signer. Run before 3, which replays the same stamp.
  local stamp chain proof stolen_rid
  stamp=$("$tmp/edgecheck" stamp "$processor_addr" "$KEYS/tls/ca.crt" "$KEYS/tls/edge.crt" "$KEYS/tls/edge.key" \
    "$NS/orders" POST /orders '{}' 2>&1)
  chain=$(printf '%s\n' "$stamp" | sed -n 's/^x-path-chain: //p')
  proof=$(printf '%s\n' "$stamp" | sed -n 's/^x-path-proof: //p')
  stolen_rid=$(chain_rid "$chain")
  mesh_req payment https://orders:8080/orders -X POST -H 'content-type: application/json' -d '{}' \
    -H "x-path-chain: $chain" -H "x-path-proof: $proof"
  if [ -n "$chain" ] && [ "$CODE" = 403 ] && printf '%s' "$BODY" | grep -q PEER_MISMATCH; then
    record PASS "7  a stamp from the processor, sent from payment's pod" "HTTP 403 PEER_MISMATCH (rid $stolen_rid)"
  else
    # The stamp itself is never printed: only whether there was one, or why not.
    [ -n "$chain" ] && stamp="a stamp, rid $stolen_rid"
    record FAIL "7  a stamp from the processor, sent from payment's pod" \
      "expected a stamp and HTTP 403 PEER_MISMATCH, got [$stamp], HTTP $CODE ($BODY)"
  fi

  # 3 - a client that sends that real chain, with its rid, and another X-Path- header, through the Gateway: the
  # edge replaces them, so orders verifies a stamp with a rid of the edge's own.
  local new_rid
  o0=$(traces orders)
  edge_req /orders -X POST -H 'content-type: application/json' -d '{}' \
    -H "x-path-chain: $chain" -H "x-path-proof: $proof" -H 'x-path-anything: replayed'
  local check3_headers="$HEADERS"
  await ord 'reason=OK receiver=orders ✓ peer=edge \(mTLS\)' added "$o0" "$(traces orders)"
  new_rid=$(printf '%s' "$ord" | sed -n 's/.* rid=\([^ ]*\) .*/\1/p')
  if [ "$CODE" = 200 ] && [ -n "$stolen_rid" ] && [ -n "$new_rid" ] && [ "$new_rid" != "$stolen_rid" ]; then
    record PASS "3  a client's X-Path- headers via the Gateway: replaced" \
      "HTTP 200; sent rid $stolen_rid, orders verified rid $new_rid"
  else
    record FAIL "3  a client's X-Path- headers via the Gateway: replaced" \
      "expected HTTP 200 and a new rid, got HTTP $CODE, sent rid '${stolen_rid}', orders [${ord:-no line}]"
  fi

  # 4 - the responses from the Gateway carry no X-Path- header (orders attests its responses with one).
  local leaked
  leaked=$(printf '%s\n%s\n' "$check1_headers" "$check3_headers" | grep -i '^x-path-' | cut -d: -f1 | sort -u |
    tr '\n' ' ')
  if [ -n "$check1_headers" ] && [ -z "$leaked" ]; then
    record PASS "4  responses from the Gateway: no X-Path- header" "checks 1 and 3: none"
  else
    record FAIL "4  responses from the Gateway: no X-Path- header" "expected none, got ${leaked:-no response headers}"
  fi

  # 5 - a route the processor is attached to but does not map: its own 403, and orders sees nothing.
  local seen
  o0=$(traces orders)
  edge_req /orders -X POST -H 'host: unmapped.example' -H 'content-type: application/json' -d '{}'
  sleep 2
  seen=$(added "$o0" "$(traces orders)" | grep -c . || true)
  if [ "$CODE" = 403 ] && printf '%s' "$BODY" | grep -q 'The edge does not serve this route.' && [ "$seen" = 0 ]; then
    record PASS "5  a route the processor does not map: refused at edge" \
      "HTTP 403 from the processor; orders saw 0 requests"
  else
    record FAIL "5  a route the processor does not map: refused at edge" \
      "expected the processor's 403 and nothing at orders, got HTTP $CODE ($BODY), orders saw $seen"
  fi

  # 6 - only Envoy reaches the processor: a pod that is not Envoy cannot connect to its gRPC port (the admin port
  # answers, so the pod's network works), and a client certificate other than the edge's is refused in the handshake.
  local connect admin refused
  kn exec checks -- curl -s -o /dev/null --connect-timeout 3 https://paztport-processor:9002/ >/dev/null 2>&1
  connect=$?
  admin=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 \
    http://paztport-processor:9090/livez 2>/dev/null)
  refused=$("$tmp/edgecheck" stamp "$processor_addr" "$KEYS/tls/ca.crt" "$KEYS/tls/orders.crt" "$KEYS/tls/orders.key" \
    "$NS/orders" POST /orders '{}' 2>&1)
  local refused_status=$?
  if { [ "$connect" = 28 ] || [ "$connect" = 7 ]; } && [ "$admin" = 200 ] && [ "$refused_status" -ne 0 ] &&
    printf '%s' "$refused" | grep -q 'bad certificate'; then
    record PASS "6  only Envoy reaches the processor" \
      "pod checks: no connection to :9002 (curl exit $connect), :9090 answers 200; CN orders: bad certificate"
  else
    record FAIL "6  only Envoy reaches the processor" \
      "expected no connection, :9090 200 and a refused handshake, got curl exit $connect, :9090 $admin, [$refused]"
  fi

  # 8 - the metrics: orders and payment count the requests they served as verified, the processor those it stamped.
  local ip text orders_ok=0 payment_ok=0 stamped_n=0 n
  for ip in $(kn get pods -l app=orders -o jsonpath='{.items[*].status.podIP}'); do
    text=$(kn exec checks -- curl -s --cacert /tls/ca.crt --cert /tls/operator.crt --key /tls/operator.key \
      --resolve "orders:8080:$ip" https://orders:8080/actuator/prometheus 2>/dev/null)
    n=$(metric_sum "$text" 'paztport_request_seconds_count{' 'mode="enforce"' 'outcome="served"' 'reason="OK"')
    orders_ok=$((orders_ok + n))
  done
  text=$(kn exec checks -- curl -s --cacert /tls/ca.crt --cert /tls/operator.crt --key /tls/operator.key \
    https://payment:8080/actuator/prometheus 2>/dev/null)
  payment_ok=$(metric_sum "$text" 'paztport_request_seconds_count{' 'mode="enforce"' 'outcome="served"' 'reason="OK"')
  for ip in $(kn get pods -l app.kubernetes.io/name=paztport-processor -o jsonpath='{.items[*].status.podIP}'); do
    text=$(kn exec checks -- curl -s "http://$ip:9090/metrics" 2>/dev/null)
    n=$(metric_sum "$text" 'paztport_edge_requests_total{outcome="stamped"}')
    stamped_n=$((stamped_n + n))
  done
  if [ "$orders_ok" -gt 0 ] && [ "$payment_ok" -gt 0 ] && [ "$stamped_n" -gt 0 ]; then
    record PASS "8  metrics: served OK at orders and payment, stamped at edge" \
      "orders $orders_ok, payment $payment_ok served OK in enforce; processor stamped $stamped_n"
  else
    record FAIL "8  metrics: served OK at orders and payment, stamped at edge" \
      "expected each above 0, got orders $orders_ok, payment $payment_ok, stamped $stamped_n"
  fi

  # 9 - an HTTP/2 request with headers and trailers and no body: Envoy sends the trailers to the processor (its mode
  # override asks for them), which refuses the request with its own 500, so it never reaches orders unstamped.
  local status refusal
  p0=$(processor_log); o0=$(traces orders)
  status=$("$tmp/edgecheck" trailers "$edge_addr" "paztport-edge.$EG_NS.svc" /orders 2>&1)
  await refusal '"outcome":"refused_body"' added "$p0" "$(processor_log)"
  seen=$(added "$o0" "$(traces orders)" | grep -c . || true)
  if [ "$status" = 500 ] && [ -n "$refusal" ] && [ "$seen" = 0 ]; then
    record PASS "9  HTTP/2 headers and trailers, no body: refused at edge" \
      "HTTP 500 from the processor (refused_body); orders saw 0"
  else
    record FAIL "9  HTTP/2 headers and trailers, no body: refused at edge" \
      "expected the processor's 500, got [$status], processor [${refusal:-no refusal}], orders saw $seen"
  fi

  # 10 - orders names a refused request's peer by its own TCP address, not by an X-Forwarded-For the client sent.
  local e0 event
  e0=$(events orders)
  mesh_req operator https://orders:8080/orders -X POST -H 'content-type: application/json' -d '{}' \
    -H 'x-forwarded-for: 203.0.113.9'
  await event 'PAZTPORT_EVENT reason=CHAIN_MISSING suspectSvc=operator ' added "$e0" "$(events orders)"
  if [ "$CODE" = 403 ] && printf '%s' "$event" | grep -qF "suspectInst=$pod_ip "; then
    record PASS "10 an event names the peer's address, not X-Forwarded-For" \
      "HTTP 403; suspectInst=$pod_ip (the pod), X-Forwarded-For was 203.0.113.9"
  else
    record FAIL "10 an event names the peer's address, not X-Forwarded-For" \
      "expected suspectInst=$pod_ip, got HTTP $CODE, [$(printf '%s' "$event" | grep -o 'suspectInst=[^ ]*')]"
  fi

  echo ""
  echo "== results =="
  printf '%s\n' "$ROWS" | sed '/^$/d' | sort -t'|' -k2,2n
  echo ""
  echo "  $pass passed, $fail failed"
  echo ""
  echo "  The cluster is still up (kubectl context $CTX); remove it with $self down"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  up) cmd_up ;;
  check) cmd_check ;;
  down) cmd_down ;;
  *)
    echo "usage: envoy-gateway.sh up|check|down" >&2
    exit 2
    ;;
esac
