# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The route and rotation suites. measure.sh sources this after common.sh, and runs suite_route and suite_rotation.
#
#   route     changes to the edge's routes under steady load on the route orders: a new URL on an existing service,
#             the HTTPRoute orders-shop (host shop.example) to orders, mapped in the chart first (its pods roll), then
#             applied with the routes' BackendTrafficPolicy extended to it; then a new service path, edge/payment,
#             with the HTTPRoute payment (POST /pay) and a BackendTLSPolicy for the Service payment, which needs a
#             rebuilt policy, rolled out in three steps with an overlap: (1) orders and payment pin the old root and
#             the new one (PAZTPORT_OVERLAP_ROOTPATHS), and orders takes the new tree's bundle; (2) the processor
#             takes the new root and bundle and maps payment, and then the route is applied; (3) the old root is
#             unpinned everywhere. Then the same change the old way, on a fresh rebuild: every holder's root replaced
#             at once, the backends' and the processor's rollouts started together; and the two side by side.
#   rotation  the edge's key rotated (policy-tool --rotate edge) under the same load, in three steps: (1) orders and
#             payment pin both keyrings (PAZTPORT_OVERLAP_KEYRINGPATHS), (2) the processor takes edge.next.key and
#             the new keyring, (3) the old keyring is unpinned. Removing the old keyring before its notAfter rests on
#             the processor refusing to start on a keyring past it, which its unit tests show; it is not shown here.
#
# The rate on orders is CHANGE_RATE, or half what the edge suite sustained there in the same run, or else
# ORDERS_DEFAULT_RATE (common.sh's orders_rate). Each step first runs a discarded warm-up, since the last change left
# new pods with cold JVMs: ramped to that rate over CHANGE_RAMP, then held at it for CHANGE_WARMUP, and says whether the
# edge held it with every response a 200: if it did not, the rate is an overload here, and the step measures a change
# under overload, which it says. Each step is then one k6 run on orders at that rate with the change CHANGE_LEAD seconds
# into it, and, on a step that applies a route, one on that route at CHANGE_NEW_RATE from just before the route is
# applied (or, once it exists, for the whole step). Each prints its runs, the window of their responses other than 200,
# the 404s on a new route before Envoy served it (expected, and counted apart from the errors), a timeline, what Envoy
# counted of its streams to the processor, and what orders and payment decided, by reason, from their traces (since a
# counter goes with the pod a rollout replaces): every pod's log since the step began, each of its files hard-linked on
# the kind node as it appears, so that none is lost to the kubelet (logs_begin). Then two lines: the traces cover the
# step (every pod's log read, and, a lower bound, as many verified OK as k6's 200s), and no request reached a backend
# without a stamp (no CHAIN_MISSING), which the first must hold for. After the steps that pin and unpin, a few requests
# one at a time show what orders accepts: a stamp under the new material while orders' own is still the old one (so the
# overlap variable is what pins it), and, once the old material is unpinned, its refusal by reason of a stamp under the
# old.
#
# The material a suite makes, a rebuilt policy or a rotated key, is made with the policy tool in its own directory,
# $RUN_DIR/material/<suite>/, which must be new, from a copy of out/keys' policy key and keyring: out/keys and
# out/policy are never written, and the suite shows they are unchanged. A rebuild also re-signs the copy's keyring,
# which no pod mounts. The pods are given the new files through the ConfigMap measure-policy and the Secret
# measure-edge-key, which kind/backends.yaml's Deployments are applied with as extra files and variables, and the
# chart as values.
#
# Every change is undone by change_undo: between the route suite's changes, at the end of each suite, when a step
# fails, and, through measure.sh's finish, on any other exit (an interrupt included) while the cluster is kept: the
# runs stopped, a helm upgrade let finish, the new routes and the BackendTLSPolicy deleted (first, so that none is
# ever served without the processor), the routes' BackendTrafficPolicy, the chart and the backends as their files
# have them, out/'s material applied again, and the pods rolled if what they mount is still not out/'s.
# shellcheck shell=bash

# The seconds of steady load before each change, the least after it, and the seconds a new route's run has before
# its route is applied.
CHANGE_LEAD=10
CHANGE_TAIL=10
CHANGE_NEW_LEAD=3
CHANGE_RAMP=30s
CHANGE_WARMUP=20s
# The length of each step's run on orders: the lead, the change, and the tail. A step that rolls the backends needs
# the most: a Spring Boot pod takes some 20 s to start here, and orders' two roll one after the other.
CHANGE_SHOP_DURATION=90s
CHANGE_PIN_DURATION=150s
CHANGE_EDGE_DURATION=90s
CHANGE_OLD_DURATION=150s
# k6's users for the run on orders hold every request in flight were each one held this long: a pod a rollout has
# just started is cold, and k6 must not run short of users, and drop requests, before the edge does.
CHANGE_POOL_SECONDS=5
# The requests one at a time that show what orders accepts once the material has moved.
CHANGE_PROBES=20
SHOP_HOST=shop.example
POLICY_TOOL="$repo/poc-sdks/java/tools/policy-tool/target/policy-tool.jar"

# The step running now: the pids of its runs, on orders and on a new route, the new route's run's name, a helm
# upgrade's pid while one runs in the background, and the pid of logs_begin's loop.
STEP_PID=""
NEW_PID=""
NEW_CASE=""
# Whether the new route's run began before its route was applied (new) or with the route there (exists).
NEW_ROUTE=""
# The step's run's length, Envoy's counters for the processor when it began, and when it began by the node's clock
# (UTC, to the millisecond), from which the backends' logs are read.
STEP_DURATION=""
STEP_ENVOY=""
STEP_SINCE=""
CHANGE_HELM_PID=""
LOGS_PID=""
# The suite's material directory, the rate on orders, and the behavioural lines that failed in the suite so far.
MATERIAL=""
CHANGE_RATE_USED=""
CHANGE_FAILS=0

# change_rate: sets CHANGE_RATE_USED, the requests a second the steps offer orders (orders_rate, from CHANGE_RATE).
change_rate() {
  orders_rate CHANGE_RATE "$CHANGE_RATE" && CHANGE_RATE_USED="$ORDERS_RATE_USED"
}

# change_fail <line>: prints a FAIL line, and counts it.
change_fail() {
  echo "  FAIL $*"
  CHANGE_FAILS=$((CHANGE_FAILS + 1))
}

# out_sums: "<sha256>  <path>" for every file in out/keys and out/policy.
out_sums() {
  python3 -c 'import hashlib, os, sys
for top in ("keys", "policy"):
    for root, dirs, files in sorted(os.walk(os.path.join(sys.argv[1], top))):
        for f in sorted(files):
            p = os.path.join(root, f)
            print(hashlib.sha256(open(p, "rb").read()).hexdigest() + "  " + os.path.relpath(p, sys.argv[1]))' \
    "$here/out"
}

# out_unchanged <sums>: the behavioural line that the suite wrote nothing in out/keys and out/policy, from out_sums
# before it and now.
out_unchanged() {
  local now
  if ! now=$(out_sums) || [ -z "$1" ]; then
    change_fail "out/keys and out/policy are unchanged: their files could not be read"
  elif [ "$now" = "$1" ]; then
    echo "  PASS out/keys and out/policy are unchanged: $(grep -c . <<<"$now") files, each with the sha256 it had" \
      "before the suite"
  else
    change_fail "out/keys and out/policy are unchanged: they differ from before the suite:"
    diff <(printf '%s\n' "$1") <(printf '%s\n' "$now") | sed -n 's/^</    before: /p; s/^>/    now:    /p'
  fi
}

# change_material <suite>: makes the suite's material directory, $RUN_DIR/material/<suite> -> MATERIAL, refusing one
# that exists, and copies into its keys/ what the policy tool reads of out/keys: the policy key and the keyring.
change_material() {
  local dir="$RUN_DIR/material/$1"
  mkdir -p "$RUN_DIR/material" && mkdir "$dir" && mkdir "$dir/keys" || {
    echo "error: could not make $dir as a new directory; a suite's material is never made over another's" >&2
    return 1
  }
  cp -p "$KEYS/policy.key" "$KEYS/keyring.json" "$dir/keys/" || return 1
  MATERIAL="$dir"
  echo "  the suite's material: ${dir#"$repo"/}, from a copy of out/keys' policy.key and keyring.json"
}

# policy_tool <args...>: the repository's policy tool, on PAZTPORT_JAVA (or java on the PATH), with none of the
# variables that would make it renew, rotate or write a reply certificate unless the args say so.
policy_tool() {
  [ -f "$POLICY_TOOL" ] || {
    echo "missing: $POLICY_TOOL (run mvn -q install -DskipTests in poc-sdks/java)" >&2
    return 1
  }
  env -u PAZTPORT_RENEW -u PAZTPORT_ROTATE -u PAZTPORT_REPLY_CERT_SVC "${PAZTPORT_JAVA:-java}" -jar "$POLICY_TOOL" "$@"
}

# root_id <root.json>: the tree's rootId, which the root names in the clear.
root_id() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["rootId"])' "$1"
}

# rebuild <name>: a policy rebuilt by the policy tool from $MATERIAL/paths.yaml and the copy's keys, into
# $MATERIAL/<name>, which must not exist (the tool would write over it).
rebuild() {
  local out="$MATERIAL/$1" said
  [ ! -e "$out" ] || { echo "error: $out exists already; a rebuild never writes over one" >&2; return 1; }
  said=$(policy_tool "$MATERIAL/paths.yaml" "$MATERIAL/keys" "$out" 2>&1) || {
    echo "error: the policy tool did not rebuild the policy: $said" >&2
    return 1
  }
  echo "  ${said//"$repo"\//}"
  echo "  its rootId $(root_id "$out/root.json"); out/policy's, which the cluster runs on," \
    "$(root_id "$POLICY/root.json")"
}

# backend_set <deployment> <change>...: applies kind/backends.yaml's Deployment of that name with the changes: each
# +<volume>/<file>=<key> projects the key of the ConfigMap measure-policy into the volume as the file, and each
# <NAME>=<value> sets the container's variable. Through kubectl apply, whose record of what it applied lets the file
# applied again take each change back out.
backend_set() {
  local json
  json=$(k create --dry-run=client -o json -f kind/backends.yaml) || return 1
  python3 -c 'import json, sys
text, docs, at = sys.stdin.read(), [], 0
decoder = json.JSONDecoder()
while text[at:].strip():
    while text[at].isspace():
        at += 1
    doc, at = decoder.raw_decode(text, at)
    docs += doc.get("items", [doc]) if doc.get("kind") == "List" else [doc]
d = [x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == sys.argv[1]][0]
spec = d["spec"]["template"]["spec"]
container = spec["containers"][0]
for change in sys.argv[2:]:
    if change.startswith("+"):
        where, _, key = change[1:].partition("=")
        volume, _, path = where.partition("/")
        [v for v in spec["volumes"] if v["name"] == volume][0]["projected"]["sources"].append(
            {"configMap": {"name": "measure-policy", "items": [{"key": key, "path": path}]}})
    else:
        name, _, value = change.partition("=")
        container["env"] = [e for e in container["env"] if e["name"] != name] + [{"name": name, "value": value}]
print(json.dumps(d))' "$@" <<<"$json" | k apply -f - >/dev/null
}

# rolled_out <deployment>...: waits for each one's rollout, until no old replica is counted.
rolled_out() {
  local d
  for d in "$@"; do
    kn rollout status "deployment/$d" --timeout=300s >/dev/null || {
      echo "error: $d did not roll out" >&2
      return 1
    }
  done
}

# upgraded <command> [helm args...]: a helm upgrade of the chart (measure_chart or one built on it), with --wait,
# its output in the case's helm log; then the processor's rollout. Prints what helm said when it failed.
upgraded() {
  "$@" --wait --timeout 5m >"$tmp/$CASE-helm.log" 2>&1 || {
    echo "error: the helm upgrade failed; helm said:" >&2
    tail -n 5 "$tmp/$CASE-helm.log" >&2
    return 1
  }
  rolled_out paztport-processor
}

# routes_policy <route>...: kind/routes.yaml applied again with its BackendTrafficPolicy, orders-routes, extended to
# the routes named (none puts it back), so that each keeps the edge's body limit as its request buffer's, and waits
# until it is accepted.
routes_policy() {
  local text extra="" route
  for route in "$@"; do extra+="    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: $route}"$'\n'; done
  text=$(sed "s/@BODY_LIMIT@/$BODY_LIMIT/" "$here/kind/routes.yaml" |
    EXTRA="$extra" awk -v after="    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: orders-unmapped}" \
      '{ print } $0 == after { printf "%s", ENVIRON["EXTRA"] }')
  [ "$(grep -c 'kind: HTTPRoute, name:' <<<"$text")" -eq $((2 + $#)) ] &&
    grep -qx "    limit: \"$BODY_LIMIT\"" <<<"$text" || {
    echo "error: kind/routes.yaml's BackendTrafficPolicy is not as routes_policy reads it, or sets no request" \
      "buffer limit" >&2
    return 1
  }
  k apply -f - <<<"$text" >/dev/null && policy_attached backendtrafficpolicy/orders-routes
}

# shop_route: the HTTPRoute orders-shop, POST /orders on the host shop.example, to orders.
shop_route() {
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orders-shop
  namespace: $NS
spec:
  parentRefs:
    - name: edge
  hostnames: [$SHOP_HOST]
  rules:
    - matches:
        - path: {type: PathPrefix, value: /orders}
      backendRefs:
        - {name: orders, port: 8080}
EOF
}

# payment_route: payment at the edge: Envoy reaching the Service payment over mutual TLS (a BackendTLSPolicy, as
# orders' in kind/backends.yaml), then the HTTPRoute payment, POST /pay, to it.
payment_route() {
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: payment
  namespace: $NS
spec:
  targetRefs:
    - {group: "", kind: Service, name: payment}
  validation:
    hostname: payment
    caCertificateRefs:
      - {group: "", kind: ConfigMap, name: mesh-ca}
EOF
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: payment
  namespace: $NS
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - path: {type: PathPrefix, value: /pay}
      backendRefs:
        - {name: payment, port: 8080}
EOF
}

# route_processed <route>: until Envoy's routes hold the HTTPRoute's with the processor's filter enabled on it, for up
# to 30 s (Envoy takes a new route a moment late); records the event then, and prints PASS or FAIL. Returns 1 on
# FAIL.
route_processed() {
  local out=""
  envoy_admin || return 1
  for _ in $(seq 1 60); do
    out=$(curl -sf "http://$ENVOY_ADMIN/config_dump?resource=dynamic_route_configs" | python3 -c 'import json, sys
found = []
for c in json.load(sys.stdin).get("configs", []):
    for vh in c.get("route_config", {}).get("virtual_hosts", []):
        for r in vh.get("routes", []):
            if r.get("name", "").startswith("httproute/paztport/%s/" % sys.argv[1]):
                found.append([k for k, v in r.get("typed_per_filter_config", {}).items()
                              if "ext_proc" in k and not v.get("disabled")])
print("none" if not found else "on " + " ".join(found[0]) if all(found) else "off")' "$1" 2>/dev/null)
    case "$out" in on*) break ;; esac
    sleep 0.5
  done
  case "$out" in
    on*)
      event "Envoy serves $1, the processor's filter enabled on it"
      echo "  PASS Envoy serves $1 with the processor's filter enabled on it (${out#on })"
      ;;
    *)
      change_fail "Envoy serves $1 with the processor's filter enabled on it: 30 s on, its route is" \
        "${out:-unreadable} (none: not in Envoy's routes; off: there without the filter)"
      return 1
      ;;
  esac
}

# route_upstream <route>: the 2xx Envoy's cluster for the HTTPRoute's first rule has had back from its backend (0
# before the cluster exists). Returns 1 when Envoy's stats cannot be read.
route_upstream() {
  local stats
  envoy_admin && stats=$(curl -sf "http://$ENVOY_ADMIN/stats") || {
    echo "error: Envoy's stats could not be read" >&2
    return 1
  }
  awk -F': ' -v c="cluster.httproute/paztport/$1/rule/0.upstream_rq_2xx" '$1 == c { n = $2 } END { printf "%d", n }' \
    <<<"$stats"
}

# The kind node's directory, on the same file system as the pods' logs (/var), where logs_begin links their files.
NODE_LOGS=/var/tmp/paztport-measure-logs

# logs_begin: on the kind node, in the background until logs_end, a loop that every 0.2 s hard-links each file of
# every orders and payment container's log (in /var/log/pods: the current one, and those the kubelet rotated past
# 10 MiB and compressed) into NODE_LOGS, once for each file (by inode), as <pod>.<inode>[.gz]. A link keeps a file's
# lines whatever the kubelet then does with it: rotates it, compresses it, or removes it with the container of a pod
# a rollout deletes; and a file is linked within 0.2 s of its making, before any line of it can go. So every line an
# orders or payment container writes in the step is kept, of every pod, rollouts included. A failed link is noted in
# NODE_LOGS/.errors; the loop writes .ready after its first pass, and .stopped when logs_end stops it, or a guard on
# the host does once this shell is gone (it gives up by itself after an hour as well). Waits for .ready.
logs_begin() {
  # shellcheck disable=SC2016 # the script runs in the node's shell
  docker exec "$(node_container)" sh -c 'd=$1
    rm -rf "$d" && mkdir "$d" || exit 1
    end=$(($(date +%s) + 3600))
    while [ ! -e "$d/.stop" ]; do
      [ "$(date +%s)" -lt "$end" ] || exit 1
      for f in /var/log/pods/"$2"_orders-*/orders/* /var/log/pods/"$2"_payment-*/payment/*; do
        [ -f "$f" ] || continue
        p=${f#/var/log/pods/*_}
        p=${p%%_*}
        i=$(stat -c %i "$f" 2>/dev/null) || continue
        case "$f" in *.gz) t="$d/$p.$i.gz" ;; *) t="$d/$p.$i" ;; esac
        [ -e "$t" ] || ln "$f" "$t" 2>>"$d/.errors" || true
      done
      [ -e "$d/.ready" ] || : >"$d/.ready"
      sleep 0.2
    done
    : >"$d/.stopped"' sh "$NODE_LOGS" "$NS" >/dev/null 2>&1 9>&- &
  LOGS_PID=$!
  forwards+=("$LOGS_PID")
  # A guard on the host, outside forwards: should this shell go without stopping the loop (killed with SIGKILL,
  # which no trap sees), it stops the loop within 2 s; it ends by itself once the loop's directory is gone.
  (
    while kill -0 "$$" 2>/dev/null && docker exec "$(node_container)" test -d "$NODE_LOGS" 2>/dev/null; do sleep 2; done
    # shellcheck disable=SC2016 # the script runs in the node's shell
    docker exec "$(node_container)" sh -c 'if [ -d "$1" ]; then : >"$1/.stop"; fi' sh "$NODE_LOGS"
  ) >/dev/null 2>&1 9>&- &
  disown "$!"
  for _ in $(seq 1 50); do
    docker exec "$(node_container)" test -e "$NODE_LOGS/.ready" && return 0
    sleep 0.2
  done
  echo "error: the loop that links the backends' logs on the kind node did not start" >&2
  return 1
}

# logs_stop: stops the loop, waits for it, and removes NODE_LOGS from the node.
logs_stop() {
  [ -n "$LOGS_PID" ] || return 0
  docker exec "$(node_container)" sh -c 'if [ -d "$1" ]; then : >"$1/.stop"; fi' sh "$NODE_LOGS" 2>/dev/null
  for _ in $(seq 1 50); do
    kill -0 "$LOGS_PID" 2>/dev/null || break
    sleep 0.2
  done
  kill "$LOGS_PID" 2>/dev/null
  wait "$LOGS_PID" 2>/dev/null
  forget "$LOGS_PID"
  LOGS_PID=""
  docker exec "$(node_container)" rm -rf "$NODE_LOGS" 2>/dev/null
}

# logs_end: a few seconds on, since a log line reaches the node's files a moment late, stops the loop, reads the
# trace lines of every file it linked into $tmp/logs/traces ("<pod> <the node's line>"), then removes them. Prints,
# and returns 1 for, what makes the reading incomplete: a loop that did not run to the end (no .stopped), a link that
# failed, a file that could not be read, or no orders or payment pod's file linked at all.
logs_end() {
  local ok=0 said
  [ -n "$LOGS_PID" ] || return 1
  sleep 3
  docker exec "$(node_container)" sh -c ': >"$1/.stop"' sh "$NODE_LOGS"
  for _ in $(seq 1 50); do
    docker exec "$(node_container)" test -e "$NODE_LOGS/.stopped" && break
    sleep 0.2
  done
  mkdir -p "$tmp/logs" || return 1
  # shellcheck disable=SC2016 # the script runs in the node's shell
  docker exec "$(node_container)" sh -c 'cd "$1" || exit 1
    [ -e .stopped ] || { echo "the loop that links the logs did not run to the end of the step" >&2; exit 1; }
    [ ! -s .errors ] || { echo "links that failed: $(head -c 300 .errors)" >&2; exit 1; }
    for f in *; do
      [ -f "$f" ] || continue
      gzip -cdf "$f" >.read || { echo "$f could not be read" >&2; exit 1; }
      grep -F "PAZTPORT_TRACE request" .read | sed "s|^|${f%%.*} |"
    done' sh "$NODE_LOGS" >"$tmp/logs/traces" 2>"$tmp/logs/said" || ok=1
  said=$(cat "$tmp/logs/said")
  [ -z "$said" ] || { echo "  the backends' logs: $said" >&2; ok=1; }
  for app in orders payment; do
    if ! docker exec "$(node_container)" sh -c 'ls "$1" | grep -q "^$2-"' sh "$NODE_LOGS" "$app"; then
      echo "  the backends' logs: no file of any $app pod was linked" >&2
      ok=1
    fi
  done
  logs_stop
  return "$ok"
}

# k6_started <name>: waits until the run's pod runs, for up to 300 s; records the event.
k6_started() {
  local phase=""
  for _ in $(seq 1 300); do
    phase=$(kn get pods -l "job-name=k6-$1" -o jsonpath='{.items[*].status.phase}' 2>/dev/null)
    [ "$phase" = Running ] && break
    sleep 1
  done
  [ "$phase" = Running ] || { echo "error: the k6 run $1 did not start (its pod: ${phase:-none})" >&2; return 1; }
  event "k6's run $1 running"
}

# step_begin <case> <duration> [<new route's settings>...]: a discarded warm-up on orders, ramped to the step's rate
# over CHANGE_RAMP and then held at it for CHANGE_WARMUP, and whether the edge held it; the step's readings before it
# (Envoy's counters for the processor), and the backends' logs noted from then (logs_begin); then its run on orders,
# at that rate for duration, and with settings given (a new route that exists already), a run on that route for the
# same length, at CHANGE_NEW_RATE, both in the background; waits until they run, and CHANGE_LEAD seconds more, so
# that the change meets steady load.
step_begin() {
  local users line
  CASE="$1"
  STEP_DURATION="$2"
  shift 2
  NEW_CASE=""
  : >"$RUN_DIR/$CASE.events"
  users=$(awk -v r="$CHANGE_RATE_USED" -v s="$CHANGE_POOL_SECONDS" 'BEGIN { printf "%d", r * s }')
  users=$(pool "$CHANGE_RATE_USED" "$users")
  line=$(k6_run "$CASE-ramp" TARGET="$EDGE/orders" BODY=small EXECUTOR=ramp PREALLOC="$users" \
    STAGES="[{\"target\": $CHANGE_RATE_USED, \"duration\": \"$CHANGE_RAMP\"}]") || return 1
  echo "  warm-up on orders, ramped to $CHANGE_RATE_USED/s over $CHANGE_RAMP (discarded): $line"
  line=$(k6_run "$CASE-warmup" TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$CHANGE_RATE_USED" \
    PREALLOC="$users" DURATION="$CHANGE_WARMUP") || return 1
  echo "  then held at $CHANGE_RATE_USED/s for $CHANGE_WARMUP (discarded): $line"
  python3 "$here/measure/summary.py" rate <(echo "warm-up $line") "$CHANGE_RATE_USED"
  case "$line" in
    *'"dropped":0,'*) ;;
    *) line="" ;;
  esac
  if [ -z "$line" ] || [ "$(sed -n 's/.*"reqs":\([0-9]*\).*/\1/p' <<<"$line")" != \
    "$(sed -n 's/.*"200":\([0-9]*\).*/\1/p' <<<"$line")" ]; then
    echo "  WARN the edge did not answer every request of the warm-up's hold 200 at $CHANGE_RATE_USED/s, before any" \
      "change: the rate is an overload here now, so what follows is a change under overload"
  fi
  envoy_admin && STEP_ENVOY=$(envoy_extproc_stats) || return 1
  STEP_SINCE=$(docker exec "$(node_container)" date -u +%Y-%m-%dT%H:%M:%S.%3NZ) && logs_begin || return 1
  echo "  the run on orders: $CHANGE_RATE_USED/s for $STEP_DURATION (k6 users: $users), the change $CHANGE_LEAD s" \
    "into it"
  k6_run "$CASE" TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$CHANGE_RATE_USED" PREALLOC="$users" \
    DURATION="$STEP_DURATION" >"$tmp/$CASE.line" 2>"$tmp/$CASE.err" &
  STEP_PID=$!
  forwards+=("$STEP_PID")
  k6_started "$CASE" || return 1
  if [ $# -gt 0 ]; then
    NEW_ROUTE=exists
    new_run "$STEP_DURATION" "$@" || return 1
  fi
  sleep "$CHANGE_LEAD"
}

# new_run <duration> <settings>...: the run on a new route, at CHANGE_NEW_RATE, in the background; waits until its
# pod runs.
new_run() {
  local duration="$1"
  shift
  NEW_CASE="$CASE-new"
  echo "  the run on the new route ($*): $CHANGE_NEW_RATE/s for $duration (k6 users: $(pool "$CHANGE_NEW_RATE"))"
  k6_run "$NEW_CASE" "$@" BODY=small EXECUTOR=rate RATE="$CHANGE_NEW_RATE" PREALLOC="$(pool "$CHANGE_NEW_RATE")" \
    DURATION="$duration" >"$tmp/$NEW_CASE.line" 2>"$tmp/$NEW_CASE.err" &
  NEW_PID=$!
  forwards+=("$NEW_PID")
  k6_started "$NEW_CASE"
}

# step_new_route <settings>...: the run on a route the step is about to apply, for what is left of the run on orders
# but a second, so that both end together; waits until it runs and CHANGE_NEW_LEAD seconds more, so that it meets
# the route before Envoy serves it. Returns 1 when less than CHANGE_TAIL and 20 s more is left.
step_new_route() {
  local started left
  started=$(event_ms "k6's run $CASE running")
  left=$(( ($(run_seconds "$STEP_DURATION" "") * 1000 - ($(node_ms) - started)) / 1000 - 1 ))
  [ "$left" -ge $((CHANGE_TAIL + 20)) ] || {
    echo "error: $left s of the run on orders are left for the new route's; the step's duration is too short" >&2
    return 1
  }
  NEW_ROUTE=new
  new_run "${left}s" "$@" && sleep "$CHANGE_NEW_LEAD"
}

# run_done <pid> <name>: waits for a run, and prints it; returns 1 when it failed.
run_done() {
  local status dropped
  wait "$1"
  status=$?
  forget "$1"
  [ ! -s "$tmp/$2.err" ] || sed 's/^/  /' "$tmp/$2.err"
  [ "$status" -eq 0 ] || return 1
  printf '  %s: %s\n' "$2" "$(cat "$tmp/$2.line")"
  run_paced "$2" || CHANGE_FAILS=$((CHANGE_FAILS + 1))
  dropped=$(sed -n 's/.*"dropped":\([0-9]*\).*/\1/p' "$tmp/$2.line")
  if [ "${dropped:-0}" -gt 0 ]; then
    echo "  k6 had no free user for $dropped of the requests it was to send, so they were never sent: every count" \
      "of $2, the errors' included, is a lower bound set by k6's pool"
  fi
}

# new_route_window <name> new|exists: a new route's run. With new (the run began before its route was applied), its
# 404s in the seconds up to the first with a 200 came before Envoy served the route, and are expected: counted
# apart, by k6's whole seconds, so that a 404 in the second of the first 200 is counted with them. Every other
# response but a 200 is an error, a 404 after that second, or before it on a route that existed (exists), included.
# Writes "<404s before> <errors> <200s>" to $RUN_DIR/<name>.split. Returns 1 when the route never answered 200.
new_route_window() {
  python3 -c 'import json, sys
run, existed = sys.argv[1], sys.argv[2] == "exists"
w = json.loads(open(run + ".window").read()[len("WINDOW "):])
expect, _, rest = open(run + ".result").read().strip().partition(" ")
r = json.loads(rest[len("RESULT "):])
n = max(len(w[k]) for k in ("expected", "5xx", "rest", "404"))
col = {k: w[k] + [0] * (n - len(w[k])) for k in ("expected", "5xx", "rest", "404")}
first = next((i for i in range(n) if col["expected"][i]), None)
oks = r["status"].get("200", 0)
if first is None:
    print("  FAIL the new route answered 200: never, in %d requests (%s)" % (r["reqs"], ", ".join(
        "%s: %d" % kv for kv in sorted(r["status"].items()) if kv[1])))
    open(run + ".split", "w").write("0 %d 0\n" % r["reqs"])
    sys.exit(1)
expected404 = [0] * n if existed else [col["404"][i] if i <= first else 0 for i in range(n)]
before = sum(expected404)
errors = r["reqs"] - oks - before
seconds = [i for i in range(n) if col["5xx"][i] + col["rest"][i] - expected404[i]]
by = dict(r["status"])
by["404"] = by.get("404", 0) - before
by.pop("200", None)
held = [i for i in range(n) if expected404[i]]
if existed:
    print("  the route existed through the run, so every response but a 200, a 404 included, is an error")
elif before:
    print("  404s before Envoy served the route: %d, in the run'"'"'s seconds +%d to +%d (the first 200 came in +%d;"
          " by whole seconds, so a 404 in +%d after that 200 is counted here); expected, and not among the errors"
          % (before, held[0], held[-1], first, first))
else:
    print("  404s before Envoy served the route: none (the first 200 came in the run'"'"'s second +%d)" % first)
open(run + ".split", "w").write("%d %d %d\n" % (before, errors, oks))
apart = "" if existed or not before else ", those 404s apart"
if errors:
    when = ("in the run'"'"'s seconds +%d to +%d" % (seconds[0], seconds[-1])) if seconds else ""
    if w["late"]:
        when += ("%s%d after the seconds counted" % (", and " if when else "", w["late"]))
    print("  %d responses other than 200%s (%s), %s" % (
        errors, apart, ", ".join("%s: %d" % kv for kv in sorted(by.items()) if kv[1]),
        when or "in no second counted"))
else:
    print("  0 responses other than 200%s" % apart)' "$RUN_DIR/$1" "$2"
}

# step_traces <200s to orders> <200s to payment> <complete>: what orders and payment decided in the step, by
# reason, from the trace lines in their logs since the step began (logs_end's $tmp/logs/traces, a line read twice
# counted once), written to $RUN_DIR/$CASE.reasons; and the two behavioural lines. <complete> is 0 when
# logs_end found every pod's log read. The coverage is a lower bound: k6's 200s are the least each backend must have
# verified OK (a 200 from a route to orders is a request orders verified, and payment too, which orders calls on
# every one; a 200 from the route payment is one payment verified), so a shortfall shows lines lost, but lines lost
# within a surplus of OK over 200s would not show; that is what <complete> is for. Returns 1 if either line is FAIL.
step_traces() {
  python3 -c 'import collections, datetime, glob, os, re, sys
logs, to_orders, to_payment, whole, out, since = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), \
    sys.argv[4] == "0", sys.argv[5], sys.argv[6]
def ms(stamp):
    """An RFC 3339 UTC time, its fraction of any length, in ms since the epoch."""
    whole, _, frac = stamp.rstrip("Z").partition(".")
    t = datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return int(t.timestamp()) * 1000 + int((frac + "000")[:3])
since = ms(since)
counts = collections.Counter()
# Each pod'"'"'s trace lines, from every file of its log linked on the node, as "<pod> <time> stdout F <line>": the
# line itself, which holds the time the service logged it and the request'"'"'s rid, is counted once for its pod, as a
# file the kubelet rotated can be linked twice (as it was, and compressed).
by_pod = collections.defaultdict(set)
for line in open(os.path.join(logs, "traces"), errors="replace"):
    parts = line.rstrip("\n").split(" ", 4)
    if len(parts) < 5 or ms(parts[1]) < since:
        continue
    by_pod[parts[0]].add(parts[4])
for pod, lines in sorted(by_pod.items()):
    app = pod.split("-")[0]
    for rest in lines:
        m = re.search(r"PAZTPORT_TRACE request rid=\S+ reason=(\S+)", rest)
        if m:
            counts[(app, m.group(1))] += 1
with open(out, "w") as f:
    for (app, reason), n in sorted(counts.items()):
        f.write("%s %s %d\n" % (app, reason, n))
print("  what orders and payment decided, from their traces (every pod'"'"'s log since the step began):")
for app in ("orders", "payment"):
    mine = sorted(((reason, n) for (a, reason), n in counts.items() if a == app), key=lambda x: (x[0] != "OK", x[0]))
    print("    %-8s %s" % (app, ", ".join("%s %d" % kv for kv in mine) or "nothing"))
ok_orders, ok_payment = counts[("orders", "OK")], counts[("payment", "OK")]
missing = counts[("orders", "CHAIN_MISSING")] + counts[("payment", "CHAIN_MISSING")]
covered = whole and ok_orders >= to_orders and ok_payment >= to_orders + to_payment
bad = 0
if covered:
    print("  PASS the traces cover the step: every file of every pod'"'"'s log was linked on the node and read;"
          " and, a lower bound, orders verified %d requests OK, no fewer than the %d 200s k6 counted on routes to"
          " orders; payment %d, no fewer than the %d on routes to orders or payment" % (
              ok_orders, to_orders, ok_payment, to_orders + to_payment))
else:
    why = [] if whole else ["not every pod'"'"'s log could be read (above)"]
    if ok_orders < to_orders:
        why.append("orders verified %d OK, fewer than the %d 200s k6 counted on routes to orders" % (
            ok_orders, to_orders))
    if ok_payment < to_orders + to_payment:
        why.append("payment verified %d OK, fewer than the %d on routes to orders or payment" % (
            ok_payment, to_orders + to_payment))
    print("  FAIL the traces cover the step: " + "; ".join(why))
    bad = 1
if missing:
    print("  FAIL no request reached a backend without a stamp: orders and payment refused %d with CHAIN_MISSING"
          " (orders %d, payment %d)" % (missing, counts[("orders", "CHAIN_MISSING")],
                                        counts[("payment", "CHAIN_MISSING")]))
    bad = 1
elif not covered:
    print("  FAIL no request reached a backend without a stamp: no CHAIN_MISSING in the traces read, but they do not"
          " cover the step, so that says nothing")
    bad = 1
else:
    print("  PASS no request reached a backend without a stamp: CHAIN_MISSING 0 at orders and at payment")
sys.exit(bad)' "$tmp/logs" "$1" "$2" "$3" "$RUN_DIR/$CASE.reasons" "$STEP_SINCE"
}

# step_end [payment]: waits for the step's runs and prints them, the window of the run on orders' responses other
# than 200 and its timeline, the new route's 404s before it was served and its errors after, what Envoy counted of
# its streams to the processor, and the backends' traces with the two lines; with payment, the new route is payment
# (its 200s are payment's), else a route to orders. Returns 1 when a run failed, or the change outlasted the run on
# orders but its tail; counts each FAIL line.
step_end() {
  local status=0 whole=0 to_orders to_payment=0 new200=0 t0 done_at end
  run_done "$STEP_PID" "$CASE" || status=1
  STEP_PID=""
  if [ -n "$NEW_CASE" ]; then
    run_done "$NEW_PID" "$NEW_CASE" || status=1
    NEW_PID=""
  fi
  logs_end || whole=1
  [ "$status" -eq 0 ] || return 1
  echo "  the run on orders:"
  window "$RUN_DIR/$CASE.fails"
  if [ -n "$NEW_CASE" ]; then
    echo "  the run on the new route:"
    new_route_window "$NEW_CASE" "$NEW_ROUTE" || CHANGE_FAILS=$((CHANGE_FAILS + 1))
    new200=$(cut -d' ' -f3 "$RUN_DIR/$NEW_CASE.split" 2>/dev/null)
    if [ -z "$new200" ]; then
      change_fail "the new route's run was summed up: $NEW_CASE.split was not written (above)"
      new200=0
    fi
  fi
  python3 "$here/measure/summary.py" timeline "$RUN_DIR/$CASE.fails" "$RUN_DIR/$CASE.events"
  echo "  Envoy counted, of its streams to the processor: $(outcomes_added "$STEP_ENVOY" "$(envoy_extproc_stats)")"
  to_orders=$(sed -n 's/.*"200":\([0-9]*\).*/\1/p' "$RUN_DIR/$CASE.result")
  if [ "${1:-}" = payment ]; then to_payment="$new200"; else to_orders=$((to_orders + new200)); fi
  step_traces "$to_orders" "$to_payment" "$whole" || CHANGE_FAILS=$((CHANGE_FAILS + 1))
  t0=$(sed -n 's/.*"t0":\([0-9]*\).*/\1/p' "$RUN_DIR/$CASE.window")
  done_at=$(event_ms "the change done")
  end=$((t0 + $(run_seconds "$STEP_DURATION" "") * 1000 - CHANGE_TAIL * 1000))
  if [ -z "$done_at" ] || [ -z "$t0" ] || [ "$done_at" -gt "$end" ]; then
    echo "error: the change was not done ${CHANGE_TAIL} s before the run on orders ended, so the window may not" \
      "cover it: give the step a longer run" >&2
    return 1
  fi
  echo "  the change took $(since "$(event_ms "the change began")" "$done_at") s; the run went on" \
    "$(since "$done_at" "$((end + CHANGE_TAIL * 1000))") s after it"
}

# backend_pods: the uid and restarts of every orders and payment pod, on one line.
backend_pods() {
  kn get pods -l 'app in (orders,payment)' \
    -o jsonpath='{range .items[*]}{.metadata.uid}:{.status.containerStatuses[0].restartCount} {end}'
}

# change_probes ok|refused <what>...: CHANGE_PROBES requests on the route orders from the pod checks, one at a time,
# and what orders counted of them (its counters, read before and after, on the same pods). With ok, PASS when every
# one was answered 200 and orders verified each OK; with refused, PASS when none was answered 200 and orders refused
# each one, for a reason other than CHAIN_MISSING (the stamp was there, and its material is not pinned). Prints the
# reasons by name. Returns 1 on FAIL.
change_probes() {
  local want="$1" what pods before after codes verdict
  shift
  what="$*"
  pods=$(backend_pods)
  before=$(backend_reasons) || { change_fail "$what: orders' counters could not be read"; return 1; }
  # shellcheck disable=SC2016 # the script runs in the pod's shell
  codes=$(kn exec checks -- sh -c 'i=0; while [ "$i" -lt "$1" ]; do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "content-type: application/json" -d "{}" "$2/orders"
    i=$((i + 1)); done' sh "$CHANGE_PROBES" "$EDGE" 2>/dev/null)
  after=$(backend_reasons) || { change_fail "$what: orders' counters could not be read"; return 1; }
  if [ "$(backend_pods)" != "$pods" ]; then
    change_fail "$what: orders' or payment's pods changed during the requests, so their counters say nothing"
    return 1
  fi
  verdict=$(python3 -c 'import collections, re, sys
want, n, codes = sys.argv[1], int(sys.argv[2]), collections.Counter(sys.argv[3].split())
def read(text):
    out = collections.Counter()
    for line in text.splitlines():
        app, series, count = line.split()
        if app == "orders" and series.startswith("paztport_request"):
            out[dict(re.findall(r"(\w+)=\"([^\"]*)\"", series)).get("reason", "?")] += int(count)
    return out
added = read(sys.argv[5]) - read(sys.argv[4])
words = "answered %s; orders decided %s" % (", ".join("%s %d" % kv for kv in sorted(codes.items())) or "nothing",
                                            ", ".join("%s %d" % kv for kv in sorted(added.items())) or "nothing")
if want == "ok":
    good = codes["200"] == n and added["OK"] == n and sum(added.values()) == n
else:
    good = (codes["200"] == 0 and sum(codes.values()) == n and sum(added.values()) == n and not added["OK"]
            and not added["CHAIN_MISSING"])
print("%s %s" % ("PASS" if good else "FAIL", words))' "$want" "$CHANGE_PROBES" "$codes" "$before" "$after")
  case "$verdict" in
    PASS*) echo "  PASS $what: of $CHANGE_PROBES requests, ${verdict#PASS }" ;;
    *) change_fail "$what: of $CHANGE_PROBES requests, ${verdict#FAIL }"; return 1 ;;
  esac
}

# processor_back: the processor on out/'s material alone (the chart as the measurements run it), rolled out, and
# the edge ready; the backends left as they are.
processor_back() {
  measure_chart --wait --timeout 5m >"$tmp/$CASE-back-helm.log" 2>&1 && wait_edge >/dev/null || {
    echo "error: the processor did not come back on out/'s material; helm said:" >&2
    tail -n 5 "$tmp/$CASE-back-helm.log" >&2
    return 1
  }
}

# chart_payment <policy dir> both|new [helm args...]: the chart with payment mapped (receiver payment) and the tree's
# bundle; its roots out/'s and the new one (both) or the new one alone (new).
chart_payment() {
  local dir="$1" roots=()
  if [ "$2" = both ]; then
    roots=(--set-file "material.roots[1]=$dir/root.json")
  else
    roots=(--set-file "material.roots[0]=$dir/root.json")
  fi
  shift 2
  measure_chart --set 'routes[2].httpRoute=payment' --set 'routes[2].receiver=payment' "${roots[@]}" \
    --set-file "material.bundle=$dir/proofs-edge.json" "$@"
}

# The changes kind/backends.yaml's Deployments are applied with: the new tree's root (and, for orders, its bundle)
# beside out/'s, pinned through the overlap or taken as their own; the new keyring the same way.
PIN_ROOT_PAYMENT="+policy/root-next.json=root.json PAZTPORT_OVERLAP_ROOTPATHS=/config/policy/root-next.json"
PIN_ROOT_ORDERS="+policy/root-next.json=root.json +policy/proofs-orders-next.json=proofs-orders.json
  PAZTPORT_OVERLAP_ROOTPATHS=/config/policy/root-next.json PAZTPORT_PROOFS_PATH=/config/policy/proofs-orders-next.json"
OWN_ROOT_PAYMENT="+policy/root-next.json=root.json PAZTPORT_ROOT_PATH=/config/policy/root-next.json"
OWN_ROOT_ORDERS="+policy/root-next.json=root.json +policy/proofs-orders-next.json=proofs-orders.json
  PAZTPORT_ROOT_PATH=/config/policy/root-next.json PAZTPORT_PROOFS_PATH=/config/policy/proofs-orders-next.json"
PIN_KEYRING="+keys/keyring-next.json=keyring.json PAZTPORT_OVERLAP_KEYRINGPATHS=/config/keys/keyring-next.json"
OWN_KEYRING="+keys/keyring-next.json=keyring.json PAZTPORT_KEYRING_PATH=/config/keys/keyring-next.json"

# route_shop: a new URL on orders, under load: orders-shop in the chart's routes (the processor's pods roll), then
# orders-routes extended to it and the route applied, with a run on its host from just before; Envoy serving it with
# the processor's filter on it, and its cluster's 2xx. Until Envoy serves orders-shop, a request for shop.example
# matches the route orders, which has no host, and is stamped as one for orders.
route_shop() {
  local before after served=0
  echo "-- (route 1) a new URL on orders: the HTTPRoute orders-shop, POST /orders on the host $SHOP_HOST: in the" \
    "chart's routes first (receiver orders; the processor's pods roll), then orders-routes extended to it and the" \
    "route applied"
  before=$(route_upstream orders-shop) || return 1
  step_begin route-shop "$CHANGE_SHOP_DURATION" || return 1
  event "the change began: helm upgrade, orders-shop in the chart's routes"
  upgraded measure_chart --set 'routes[2].httpRoute=orders-shop' --set 'routes[2].receiver=orders' || return 1
  event "helm upgrade done: the processor's pods rolled"
  step_new_route TARGET="$EDGE/orders" HOST="$SHOP_HOST" || return 1
  routes_policy orders-shop && shop_route || return 1
  event "orders-routes extended to orders-shop, and the route applied"
  policy_attached envoyextensionpolicy/paztport-processor || return 1
  # A route Envoy serves without the processor is a FAIL, not a stop: the step's runs and traces still say what
  # reached orders.
  route_processed orders-shop || served=1
  event "the change done"
  step_end || return 1
  after=$(route_upstream orders-shop) || return 1
  if [ $((after - before)) -gt 0 ]; then
    echo "  PASS orders-shop served $SHOP_HOST: Envoy's cluster for it had $((after - before)) 2xx back from orders," \
      "each a request orders verified (its traces, above)"
  else
    change_fail "orders-shop served $SHOP_HOST: Envoy's cluster for it had no 2xx back from orders"
  fi
  [ "$served" -eq 0 ]
}

# route_overlap: edge/payment and the route payment rolled out with the overlap, in three steps, then the old root
# shown unpinned.
route_overlap() {
  local m="$MATERIAL/overlap" served=0
  echo "-- (route 2) a new service path, edge/payment, and the route payment (POST /pay, Envoy to payment over mutual" \
    "TLS), rolled out with an overlap; the policy rebuilt from ${MATERIAL#"$repo"/}/paths.yaml, which adds" \
    "[edge, payment] to out/'s two paths:"
  rebuild overlap || return 1
  apply_files "$NS" configmap measure-policy "root.json=$m/root.json" "proofs-orders.json=$m/proofs-orders.json" \
    >/dev/null || return 1
  echo ""
  echo "-- (route 2, step 1) orders and payment pin out/'s root and the new one (PAZTPORT_OVERLAP_ROOTPATHS), and" \
    "orders takes the new tree's bundle: payment first, since orders' new bundle stamps its calls to payment under" \
    "the new tree; then orders"
  step_begin route-overlap-1 "$CHANGE_PIN_DURATION" || return 1
  event "the change began: payment rolled, pinning both roots"
  # shellcheck disable=SC2086 # the changes split on space
  backend_set payment $PIN_ROOT_PAYMENT && rolled_out payment || return 1
  event "payment rolled out; orders rolled, pinning both roots, on the new bundle"
  # shellcheck disable=SC2086
  backend_set orders $PIN_ROOT_ORDERS && rolled_out orders || return 1
  event "the change done"
  step_end || return 1
  echo ""
  echo "-- (route 2, step 2) the processor takes the new root beside out/'s, the new tree's bundle, and payment" \
    "mapped (helm upgrade; its pods roll); then the route payment applied, with orders-routes extended to it and a" \
    "BackendTLSPolicy for the Service payment"
  step_begin route-overlap-2 "$CHANGE_EDGE_DURATION" || return 1
  event "the change began: helm upgrade, the new root and bundle, payment mapped"
  upgraded chart_payment "$m" both || return 1
  event "helm upgrade done: the processor's pods rolled"
  step_new_route TARGET="$EDGE/pay" || return 1
  routes_policy payment && payment_route || return 1
  event "orders-routes extended to payment, its BackendTLSPolicy and the route applied"
  policy_attached envoyextensionpolicy/paztport-processor && policy_attached backendtlspolicy/payment || return 1
  route_processed payment || served=1
  event "the change done"
  step_end payment || return 1
  [ "$served" -eq 0 ] || return 1
  change_probes ok "orders accepts a stamp under the new tree while its own root is still out/'s, through the root" \
    "PAZTPORT_OVERLAP_ROOTPATHS pins (the processor stamps under the new tree alone now)" || true
  echo ""
  echo "-- (route 2, step 3) the old root unpinned everywhere: orders and payment take the new root as their own" \
    "(no overlap), and the processor the new root alone (helm upgrade), started together"
  step_begin route-overlap-3 "$CHANGE_PIN_DURATION" TARGET="$EDGE/pay" || return 1
  event "the change began: orders, payment and the processor rolled onto the new root alone"
  # shellcheck disable=SC2086
  backend_set payment $OWN_ROOT_PAYMENT && backend_set orders $OWN_ROOT_ORDERS || return 1
  upgraded chart_payment "$m" new &
  CHANGE_HELM_PID=$!
  rolled_out payment orders || return 1
  wait "$CHANGE_HELM_PID" || { CHANGE_HELM_PID=""; return 1; }
  CHANGE_HELM_PID=""
  event "the change done"
  step_end payment || return 1
  echo ""
  echo "-- (route 2, after step 3) the route payment deleted (first, so that it is never served without the" \
    "processor), and the processor alone put back on out/'s material, the old tree: orders and payment keep the new" \
    "root alone"
  CASE=route-overlap-unpinned
  : >"$RUN_DIR/$CASE.events"
  kn delete httproute payment --ignore-not-found >/dev/null && processor_back || return 1
  change_probes refused "orders refuses a stamp under out/'s old tree once it is unpinned, for its reason" || true
}

# route_old_way: the same change, on a fresh rebuild, every holder's root replaced at once.
route_old_way() {
  local m="$MATERIAL/old-way" served=0
  echo "-- (route 3) the same change the old way, on a fresh rebuild of the same paths, every holder's root replaced" \
    "at once: orders and payment take the new root as their own (and orders the new bundle), and the processor the" \
    "new root alone, the new bundle and payment mapped (helm upgrade), their rollouts started together; then the" \
    "route payment applied, as in step 2"
  rebuild old-way || return 1
  apply_files "$NS" configmap measure-policy "root.json=$m/root.json" "proofs-orders.json=$m/proofs-orders.json" \
    >/dev/null || return 1
  step_begin route-old-way "$CHANGE_OLD_DURATION" || return 1
  event "the change began: orders, payment and the processor rolled onto the new root at once"
  # shellcheck disable=SC2086
  backend_set payment $OWN_ROOT_PAYMENT && backend_set orders $OWN_ROOT_ORDERS || return 1
  upgraded chart_payment "$m" new &
  CHANGE_HELM_PID=$!
  rolled_out payment orders || return 1
  wait "$CHANGE_HELM_PID" || { CHANGE_HELM_PID=""; return 1; }
  CHANGE_HELM_PID=""
  event "the rollouts done"
  step_new_route TARGET="$EDGE/pay" || return 1
  routes_policy payment && payment_route || return 1
  event "orders-routes extended to payment, its BackendTLSPolicy and the route applied"
  policy_attached envoyextensionpolicy/paztport-processor && policy_attached backendtlspolicy/payment || return 1
  route_processed payment || served=1
  event "the change done"
  step_end payment && [ "$served" -eq 0 ]
}

# route_compare: the overlap's three steps against the old way's one, as the steps' files have them, one run each
# and so no spread: first the material refusals, what the backends refused for any reason but OK, EXPIRED (a stamp
# past orders' maxAgeMs, as a cold pod's queue makes) and CHAIN_MISSING (shown by each step's own line), which is
# what the overlap is for; then, apart, everything the rollouts cost: the requests on orders and on /pay and their
# responses other than 200, and the age refusals. The overlap rolls the backends twice (payment then orders, then
# both together) and the processor twice; the old way each once, all at the same time. The load on /pay differs:
# the overlap's runs from just before its route is applied through step 3's rollouts, the old way's only after its
# rollouts, since the route comes after them.
route_compare() {
  echo "-- the overlap against the old way: the same change (a rebuilt policy adding edge/payment, and the route" \
    "payment), $CHANGE_RATE_USED/s on orders throughout; one run of each, so no spread"
  python3 -c 'import json, os, sys
d = sys.argv[1]
ROLLOUT = ("OK", "EXPIRED", "CHAIN_MISSING")
def side(label, rollouts, cases):
    reqs = bad = 0
    by, pay, refused = {}, [0, 0, 0, 0], {}
    for c in cases:
        expect, _, rest = open(os.path.join(d, c + ".result")).read().strip().partition(" ")
        r = json.loads(rest[len("RESULT "):])
        reqs += r["reqs"]
        for s, n in r["status"].items():
            if s != "200" and n:
                by[s] = by.get(s, 0) + n
                bad += n
        split = os.path.join(d, c + "-new.split")
        if os.path.exists(split):
            before, errors, oks = map(int, open(split).read().split())
            nr = json.loads(open(os.path.join(d, c + "-new.result")).read().partition(" ")[2][len("RESULT "):])
            pay = [pay[0] + nr["reqs"], pay[1] + before, pay[2] + errors, pay[3] + oks]
        for line in open(os.path.join(d, c + ".reasons")):
            app, reason, n = line.split()
            if reason != "OK":
                refused[(app, reason)] = refused.get((app, reason), 0) + int(n)
    material = {k: n for k, n in refused.items() if k[1] not in ROLLOUT}
    age = {k: n for k, n in refused.items() if k[1] == "EXPIRED"}
    words = lambda d: ", ".join("%s %s %d" % (a, r, n) for (a, r), n in sorted(d.items())) or "none"
    print("  %s (%s; %s):" % (label, ", ".join(cases), rollouts))
    print("    material refusals at the backends: %s" % words(material))
    print("    what the rollouts cost, apart: orders %d requests, %d other than 200%s; /pay %d requests, %d 404s before"
          " it was served, %d other than 200, %d 200s; age refusals (EXPIRED) %s" % (
              reqs, bad, " (" + ", ".join("%s: %d" % kv for kv in sorted(by.items())) + ")" if bad else "",
              pay[0], pay[1], pay[2], pay[3], words(age)))
side("the overlap, three steps", "the backends rolled twice, payment then orders and then both, the processor twice",
     ["route-overlap-1", "route-overlap-2", "route-overlap-3"])
side("the old way, one step", "the backends and the processor rolled once, together", ["route-old-way"])' "$RUN_DIR"
  echo "  the load on /pay differs: the overlap's ran from just before its route was applied, through step 3's" \
    "rollouts; the old way's only after its rollouts, since its route comes after them"
}

# rotation_steps: the edge's key rotated on the material copy, then rolled out in three steps under load, the new
# keyring shown pinned through the overlap and, once the old is unpinned, a stamp under the old key refused.
rotation_steps() {
  local said keys="$MATERIAL/keys"
  said=$(policy_tool --rotate edge "$keys" 2>&1) || {
    echo "error: the policy tool did not rotate edge's key: $said" >&2
    return 1
  }
  echo "  ${said//"$repo"\//}"
  apply_files "$NS" configmap measure-policy "keyring.json=$keys/keyring.next.json" >/dev/null &&
    apply_files "$NS" secret measure-edge-key "edge.key=$keys/edge.next.key" >/dev/null || return 1
  echo ""
  echo "-- (rotation, step 1) orders and payment pin out/'s keyring and keyring.next.json" \
    "(PAZTPORT_OVERLAP_KEYRINGPATHS), rolled together"
  step_begin rotation-1 "$CHANGE_PIN_DURATION" || return 1
  event "the change began: orders and payment rolled, pinning both keyrings"
  # shellcheck disable=SC2086
  backend_set payment $PIN_KEYRING && backend_set orders $PIN_KEYRING && rolled_out payment orders || return 1
  event "the change done"
  step_end || return 1
  echo ""
  echo "-- (rotation, step 2) the processor takes edge.next.key and keyring.next.json (helm upgrade; its pods roll)"
  step_begin rotation-2 "$CHANGE_EDGE_DURATION" || return 1
  event "the change began: helm upgrade, edge.next.key and keyring.next.json"
  upgraded measure_chart --set material.existingKeySecret=measure-edge-key \
    --set-file "material.keyrings[0]=$keys/keyring.next.json" || return 1
  event "the change done"
  step_end || return 1
  change_probes ok "orders accepts a stamp under edge's new key while its own keyring is still out/'s, through the" \
    "keyring PAZTPORT_OVERLAP_KEYRINGPATHS pins (the processor signs with the new key alone now)" || true
  echo ""
  echo "-- (rotation, step 3) the old keyring unpinned: orders and payment take keyring.next.json as their own (no" \
    "overlap), rolled together"
  step_begin rotation-3 "$CHANGE_PIN_DURATION" || return 1
  event "the change began: orders and payment rolled onto the new keyring alone"
  # shellcheck disable=SC2086
  backend_set payment $OWN_KEYRING && backend_set orders $OWN_KEYRING && rolled_out payment orders || return 1
  event "the change done"
  step_end || return 1
  echo ""
  echo "-- (rotation, after step 3) the processor alone put back on out/'s material, edge's old key: orders and" \
    "payment keep the new keyring alone"
  CASE=rotation-unpinned
  : >"$RUN_DIR/$CASE.events"
  processor_back || return 1
  change_probes refused "orders refuses a stamp under edge's old key once its keyring is unpinned, for its reason" ||
    true
}

# change_undo: every change put back (see the top of the file). Returns 1 when any of it could not be done, saying
# which; a release a helm upgrade left pending (one stopped half-way, by an interrupt) is a FAIL, and nothing here
# rolls it back.
change_undo() {
  local ok=0 log="$tmp/change-undo-helm.log" release pid object
  for pid in $STEP_PID $NEW_PID; do
    kill "$pid" 2>/dev/null
    forget "$pid"
  done
  STEP_PID=""
  NEW_PID=""
  [ -z "$CHANGE_HELM_PID" ] || wait "$CHANGE_HELM_PID" 2>/dev/null
  CHANGE_HELM_PID=""
  logs_stop
  kn delete job -l app=k6 --ignore-not-found >/dev/null 2>&1
  kn delete httproute orders-shop payment --ignore-not-found >/dev/null &&
    kn delete backendtlspolicy payment --ignore-not-found >/dev/null || {
    echo "error: could not delete the routes orders-shop and payment, or payment's BackendTLSPolicy" >&2
    ok=1
  }
  routes_policy || { echo "error: could not put orders-routes back as kind/routes.yaml has it" >&2; ok=1; }
  release=$(helm_release)
  case "$release" in
    pending-*)
      echo "  FAIL the processor's chart release is $release: a helm upgrade was stopped half-way, and nothing here" \
        "rolls it back; the rest is put back, the chart is not: remove the cluster with" \
        "poc-demos/envoy-gateway/envoy-gateway.sh down"
      ok=1
      ;;
    *)
      measure_chart --force-conflicts --wait --timeout 5m >"$log" 2>&1 || {
        echo "error: could not put the processor's chart back; helm said:" >&2
        tail -n 5 "$log" >&2
        ok=1
      }
      ;;
  esac
  make_material >/dev/null || { echo "error: could not apply out/'s material again" >&2; ok=1; }
  k apply -f kind/backends.yaml >/dev/null && rolled_out orders payment paztport-processor || {
    echo "error: could not put orders and payment back as kind/backends.yaml has them" >&2
    ok=1
  }
  if ! material_matches 2>/dev/null; then
    kn rollout restart deployment/orders deployment/payment deployment/paztport-processor >/dev/null &&
      rolled_out orders payment paztport-processor && material_matches || {
      echo "error: the pods' material is not out/'s, even rolled" >&2
      ok=1
    }
  fi
  for object in $SUITE_MATERIAL; do
    kn delete "$object" --ignore-not-found >/dev/null || ok=1
  done
  wait_measure >/dev/null || { echo "error: the edge is not ready" >&2; ok=1; }
  if [ "$ok" -eq 0 ]; then
    echo "  put back: the routes and BackendTLSPolicies the baseline's, the chart and the backends as their files" \
      "have them, and every pod's material out/'s ($MATERIAL_PODS pods)"
  fi
  return "$ok"
}

suite_route() {
  local status=0 step first=1 sums
  echo "== route: a new URL on orders, and a new service path rolled out with an overlap and the old way, under load"
  baseline_reset
  CHANGE_FAILS=0
  envoy_admin && change_rate && sums=$(out_sums) && change_material route || return 1
  printf 'paths:\n  - [edge, orders]\n  - [edge, orders, payment]\n  - [edge, payment]\n' >"$MATERIAL/paths.yaml"
  UNDO="change_undo"
  for step in route_shop route_overlap route_old_way; do
    # Each change starts from the baseline: what the last one changed is put back first.
    if [ -z "$first" ] && ! change_undo; then
      echo "error: what the last change made could not all be put back; skipping the rest" >&2
      status=1
      break
    fi
    first=""
    echo ""
    "$step" || {
      echo "error: $step stopped; putting back what it changed and skipping the rest" >&2
      status=1
      break
    }
  done
  undo || status=1
  echo ""
  [ "$status" -ne 0 ] || route_compare || status=1
  echo "-- after the changes"
  out_unchanged "$sums"
  [ "$CHANGE_FAILS" -eq 0 ] || status=1
  return "$status"
}

suite_rotation() {
  local status=0 sums
  echo "== rotation: the edge's key rotated under load, in three steps"
  baseline_reset
  CHANGE_FAILS=0
  envoy_admin && change_rate && sums=$(out_sums) && change_material rotation || return 1
  UNDO="change_undo"
  rotation_steps || {
    echo "error: the rotation stopped; putting back what it changed" >&2
    status=1
  }
  undo || status=1
  echo "-- after the rotation"
  out_unchanged "$sums"
  [ "$CHANGE_FAILS" -eq 0 ] || status=1
  return "$status"
}
