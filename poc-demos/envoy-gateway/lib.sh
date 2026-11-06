# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# What envoy-gateway.sh and measure.sh share: the names, the cluster and its material, the chart and the routes, the
# waits, and the log and metrics readers. Each sources it; it sets here (this directory) and repo, and runs nothing.
# Every kubectl and helm call names the cluster's own context, so no other cluster is touched.
# shellcheck shell=bash

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

CLUSTER=paztport-envoy-gateway
CTX="kind-$CLUSTER"
NS=paztport
EG_NS=envoy-gateway-system
EG_CHART=oci://docker.io/envoyproxy/gateway-helm
EG_VERSION=v1.10.0
EG_IMAGE=docker.io/envoyproxy/gateway:v1.10.0@sha256:c2243d43518bed91d3ed8c2db849a4b7a14ac9b96eb019f2ab104bb1ca8572b1
# The most bytes of request body the edge stamps: the processor's limit (the chart's bodyLimit) and the routes'
# request buffer (requestBuffer.limit in kind/routes.yaml and kind/measure.yaml), from this one number.
BODY_LIMIT=1048576
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
  local args=() kv
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

# install_chart [helm args...]: installs or upgrades the processor's chart for the Gateway edge and the route orders,
# the edge's key, the processor's TLS and the mesh CA named as the Secrets and ConfigMap above, the public material
# passed as files. The routes' own BackendTrafficPolicy (kind/routes.yaml) carries the body limit, so the chart makes
# none: Envoy Gateway would attach only the older of the two.
install_chart() {
  helm --kube-context "$CTX" upgrade --install paztport "$here/chart" -n "$NS" \
    --set image.tag=dev \
    --set gateway.name=edge \
    --set 'routes[0].httpRoute=orders' --set 'routes[0].receiver=orders' \
    --set bodyLimit="$BODY_LIMIT" \
    --set backendTrafficPolicy=false \
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

# apply_routes <file>: applies routes and their BackendTrafficPolicy (kind/routes.yaml, kind/measure.yaml) with the
# request buffer limit set to BODY_LIMIT.
apply_routes() {
  local text
  text=$(sed "s/@BODY_LIMIT@/$BODY_LIMIT/" "$here/$1")
  grep -qx "    limit: \"$BODY_LIMIT\"" <<<"$text" || {
    echo "$1 sets no request buffer limit" >&2
    return 1
  }
  k apply -f - <<<"$text"
}

# policy_status <kind/name>: one line for each of the policy's ancestors (each Gateway its targets attach to): the
# status of its Accepted condition, its reason, and the status of its Overridden condition, if any, then "-".
policy_status() {
  local accepted='.conditions[?(@.type=="Accepted")]' overridden='.conditions[?(@.type=="Overridden")]'
  kn get "$1" -o jsonpath="{range .status.ancestors[*]}{$accepted.status} {$accepted.reason} {$overridden.status}-
{end}" 2>/dev/null
}

# policy_attached <kind/name>: until the policy is accepted on every ancestor, and overridden on none, for up to 60 s.
# A policy that conflicts with an older one on the same target is not accepted (reason Conflicted), and one that a
# policy on a route's rule replaces is marked Overridden.
policy_attached() {
  local lines
  for _ in $(seq 1 120); do
    lines=$(policy_status "$1")
    if [ -n "$lines" ] && ! grep -qvE '^True Accepted (False)?-$' <<<"$lines"; then return 0; fi
    sleep 0.5
  done
  echo "$1 is not accepted on every ancestor, or is overridden: [$(tr '\n' ';' <<<"$lines")]" >&2
  return 1
}

# wait_edge: until the Gateway is programmed, the processor's EnvoyExtensionPolicy and the routes' BackendTrafficPolicy
# are accepted on every ancestor and overridden on none, its Envoy is available, and orders, payment, the processor
# and the pod checks are ready.
wait_edge() {
  k -n "$NS" wait --for=condition=Programmed gateway/edge --timeout=180s &&
    policy_attached envoyextensionpolicy/paztport-processor &&
    policy_attached backendtrafficpolicy/orders-routes &&
    k -n "$EG_NS" wait --for=condition=Available deployment \
      -l "gateway.envoyproxy.io/owning-gateway-name=edge,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
      --timeout=180s &&
    for d in orders payment paztport-processor; do
      k -n "$NS" rollout status "deployment/$d" --timeout=300s || return 1
    done &&
    k -n "$NS" wait --for=condition=Ready pod/checks --timeout=120s
}

# Logs. Each snapshot is every line so far; added <before> <now> prints the lines in now that before lacks.
processor_log() { kn logs -l app.kubernetes.io/name=paztport-processor --tail=-1 --prefix 2>/dev/null; }
traces() { kn logs -l "app=$1" --tail=-1 --prefix 2>/dev/null | grep -F 'PAZTPORT_TRACE request'; }
events() { kn logs -l "app=$1" --tail=-1 --prefix 2>/dev/null | grep -F 'PAZTPORT_EVENT'; }
added() {
  if [ -z "$1" ]; then printf '%s\n' "$2"; else grep -vxF -f <(printf '%s\n' "$1") <<<"$2"; fi
}

# await <var> <pattern> <before> <command...>: runs command (a log snapshot) again and again, until the lines it
# prints that before lacks hold one matching the extended regular expression pattern (logs reach kubectl a moment
# late), for up to 10 s; sets var to that line, or empty.
await() {
  local var="$1" pattern="$2" before="$3" line=""
  shift 3
  for _ in $(seq 1 20); do
    line=$(added "$before" "$("$@")" | grep -E -- "$pattern" | tail -n1)
    [ -n "$line" ] && break
    sleep 0.5
  done
  printf -v "$var" '%s' "$line"
}

# forward <namespace> <svc/name|pod/name> <port>: kubectl port-forward to it in the background -> FORWARDED (the
# local address). The caller sets tmp (a scratch directory) and forwards (an array, of the forwards' pids, which it
# kills on exit). The forward bypasses the NetworkPolicy, as kubectl's own traffic does.
forward() {
  local log="$tmp/forward-${2//\//-}.log" addr=""
  # kubectl itself, not through k: a function in the background is a subshell, whose pid is not kubectl's, so that
  # killing it would leave the forward running.
  kubectl --context "$CTX" -n "$1" port-forward "$2" ":$3" >"$log" 2>&1 &
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

# metric_sum <text> <string>...: the sum of the samples in the metrics text whose line holds every string given.
metric_sum() {
  local text="$1" p
  shift
  for p in "$@"; do text=$(printf '%s\n' "$text" | grep -F -- "$p"); done
  printf '%s\n' "$text" | awk 'NF { s += $NF } END { printf "%d", s }'
}
