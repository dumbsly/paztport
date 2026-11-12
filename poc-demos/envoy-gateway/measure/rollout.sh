# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The rollout, observe and gotchas suites. measure.sh sources this after common.sh, and runs suite_rollout,
# suite_observe and suite_gotchas.
#
#   rollout  Paztport adopted under load, in the order production takes it, on a route of its own: the HTTPRoute
#            orders-adopt (host adopt.example) to orders, which the chart's routes do not name, with orders and
#            payment as they ran before Paztport was installed (the edge suite's baseline, measure/load.sh's
#            backends_without); then (step 1) the processor mapped to it, orders-adopt added to the chart's routes with
#            attach=false, so that the processor's pods roll and map it while its EnvoyExtensionPolicy does not target
#            it; then (step 2) the processor attached to it, attach=true, which rolls no pod; then (step 3) orders and
#            payment rolled straight into enforce: orders first, then payment, since a callee in enforce refuses every
#            call its caller does not stamp yet. No audit step: audit is for before production, where every path is
#            signed before its release. Then a request straight to orders, past the Gateway, refused CHAIN_MISSING;
#            and orders-adopt removed, and shown gone.
#   observe  what the edge and the backends count under load (the processor's outcomes, how long stamping took and
#            the bodies' sizes from its histograms, how long its material has left, the backends' reasons); then
#            requests that carry a marker, in the body and in a header of the client's, and a stamp the processor
#            made (edgecheck stamp, as Envoy asks for one) sent through the Gateway as a client's: none of them, and
#            not the edge's key, in any line the processor logged; and what Envoy's access log and the backends' logs
#            hold of them, as findings.
#   gotchas  two routes an operator could add that undo what the edge's stamp is for: (a) orders-rewrite, whose path
#            Envoy rewrites after the processor stamped the request, refused at orders (BINDING_MISMATCH); (b) a retry
#            on 5xx: with payment scaled to 0, so that orders answers 500 to every order, the route orders (its
#            retries confined to what never reached orders) against orders-retry, whose own BackendTrafficPolicy
#            retries a 5xx, so that orders is sent the same stamp again.
#
# The rate on orders in rollout and observe is CHANGE_RATE, or half what the edge suite sustained there in the same
# run, or else ORDERS_DEFAULT_RATE (common.sh's orders_rate); rollout's steps are measure/change.sh's (step_begin and
# step_end: a discarded warm-up, then a run with the change CHANGE_LEAD seconds into it, its window and timeline, and
# the backends' traces from every pod's log, hard-linked on the kind node). Each suite undoes what it changed on any
# exit while the cluster is kept: a test route deleted first, so that none is served without the processor, then the
# rest as change.sh's change_undo puts it back, payment's replicas and the backends' environment included.
# shellcheck shell=bash

ADOPT_HOST=adopt.example
RETRY_HOST=retry.example
REWRITE_PATH=/api/orders
# The length of each rollout step's run on orders: the lead, the change, and the tail. Step 1 rolls the processor's
# pods; step 3 rolls orders' two replicas, then payment's two, one pod at a time (surge 1, none unavailable), each a
# Spring Boot pod that takes some 20 s to start here and drains for 5 s once told to stop; the drain is not in the
# roll's length, since a rollout counts a pod gone as soon as it is told to stop.
ROLLOUT_MAP_DURATION=90s
ROLLOUT_ATTACH_DURATION=90s
ROLLOUT_ENFORCE_DURATION=150s
# The requests one at a time that show what orders does with a rewritten path, and what it does with a retry.
GOTCHA_PROBES=10
GOTCHA_REQUESTS=50

# --- the shared pieces ---

# backends_counters <when>: what orders' and payment's running pods have counted since they started, by mode,
# outcome and reason, read from their /actuator/prometheus; or that they count nothing (neither runs Paztport).
backends_counters() {
  local reading
  if ! reading=$(backend_reasons 2>&1); then
    echo "  orders' and payment's counters $1: could not be read: $reading"
    return
  fi
  if [ -z "$reading" ]; then
    echo "  orders' and payment's counters $1: none (neither runs Paztport, so neither counts a request)"
    return
  fi
  echo "  orders' and payment's counters $1, since their pods started:"
  python3 -c 'import re, sys
for line in sys.argv[1].splitlines():
    fields = line.split()
    if len(fields) != 3:
        print("    (not a counter line: %s)" % line)
        continue
    app, series, n = fields
    labels = dict(re.findall(r"(\w+)=\"([^\"]*)\"", series))
    if series.startswith("paztport_request"):
        name, keys = "request", ("mode", "outcome", "reason")
    elif series.startswith("paztport_outbound_retry"):
        name, keys = "outbound retry", ("failure", "outcome")
    else:
        name, keys = "response checked", ("mode", "outcome", "reason")
    print("    %-8s %-16s %-40s %s" % (app, name, " ".join("%s=%s" % (k, labels[k]) for k in keys if k in labels),
          n))' "$reading"
}

# routes_gone <route>...: the behavioural line that the test routes are gone: no HTTPRoute of those names, none the
# target of a BackendTrafficPolicy or of the processor's EnvoyExtensionPolicy, and none in Envoy's routes (waited for
# up to 30 s, as Envoy takes the change a moment late). Returns 1 on FAIL.
routes_gone() {
  local left targets="" envoy="" route out policies
  if left=$(kn get httproutes -o jsonpath='{.items[*].metadata.name}'); then
    left=$(tr ' ' '\n' <<<"$left" | grep -xF -f <(printf '%s\n' "$@") | paste -sd ' ' -)
  else
    left="(the HTTPRoutes could not be read)"
  fi
  # Read first, each step with its own status: through a pipe, a failed read would leave no target, as none would.
  if ! policies=$(kn get backendtrafficpolicies,envoyextensionpolicies -o json); then
    targets="(the policies could not be read)"
  elif ! targets=$(python3 -c 'import json, sys
names = set(sys.argv[2:])
print(" ".join("%s/%s->%s" % (p["kind"], p["metadata"]["name"], t["name"]) for p in json.loads(sys.argv[1])["items"]
               for t in p["spec"].get("targetRefs", []) if t.get("name") in names))' "$policies" "$@"); then
    targets="(the policies could not be parsed)"
  fi
  envoy_admin || return 1
  for _ in $(seq 1 30); do
    envoy=""
    for route in "$@"; do
      out=$(route_filter "$route") || out="(unreadable)"
      [ "$out" = none ] || envoy+="$route ($out) "
    done
    [ -n "$envoy" ] || break
    sleep 1
  done
  if [ -z "$left" ] && [ -z "$targets" ] && [ -z "$envoy" ]; then
    echo "  PASS $* gone: no HTTPRoute of the name, none a target of a BackendTrafficPolicy or of the processor's" \
      "EnvoyExtensionPolicy, and none in Envoy's routes"
  else
    change_fail "$* gone: expected none, got HTTPRoutes [${left:-none}], policy targets [${targets:-none}]," \
      "in Envoy's routes [${envoy% }]"
    return 1
  fi
}

# --- rollout ---

# adopt_route: the HTTPRoute orders-adopt, POST /orders on the host adopt.example, to orders.
adopt_route() {
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orders-adopt
  namespace: $NS
spec:
  parentRefs:
    - name: edge
  hostnames: [$ADOPT_HOST]
  rules:
    - matches:
        - path: {type: PathPrefix, value: /orders}
      backendRefs:
        - {name: orders, port: 8080}
EOF
}

# adopt_plain: orders and payment without Paztport, rolled out; then orders-routes extended to orders-adopt (its
# retries and the body limit) and the route applied, which Envoy serves with no processor; and the edge answering 200
# on it.
adopt_plain() {
  local out="" code=""
  echo "-- (rollout, before) orders and payment as they ran before Paztport was installed: the starter's" \
    "auto-configuration excluded (SPRING_AUTOCONFIGURE_EXCLUDE), orders on Spring Boot's own mutual TLS client to" \
    "payment (SPRING_HTTP_CLIENTS_SSL_BUNDLE=mesh), as the edge suite's baseline; then the HTTPRoute orders-adopt" \
    "(host $ADOPT_HOST) to orders, with orders-routes extended to it, which the chart's routes do not name"
  backends_without && rolled_out orders payment || return 1
  echo "  the environment that differs, as the cluster runs it now (in enforce, kind/backends.yaml's):"
  diff <(backends_env file) <(backends_env) | sed -n 's/^</    in enforce: /p; s/^>/    now:        /p'
  routes_policy orders-adopt && adopt_route || return 1
  for _ in $(seq 1 60); do
    out=$(route_filter orders-adopt)
    code=$(edge_posts 1 /orders "$ADOPT_HOST")
    [ "$out" = off ] && [ "$code" = 200 ] && break
    sleep 1
  done
  [ "$out" = off ] && [ "$code" = 200 ] || {
    echo "error: orders-adopt is not served without the processor: Envoy has it ${out:-unread}, and it answers" \
      "${code:-nothing}" >&2
    return 1
  }
  echo "  Envoy serves orders-adopt without the processor's filter, and it answers 200"
  backends_counters "before the steps"
}

# map_balance <Envoy's before> <after> <the run's .result>: that the mapping step touched no request. The route has no
# filter, so Envoy starts no stream to the processor for it in the run; and the processor's pods rolling is no reason
# for any response but 200. Fails when Envoy started a stream; a response other than 200 is printed only.
map_balance() {
  python3 -c 'import json, sys
def words(text):
    return {k: int(v) for k, v in (w.split("=") for w in text.split())}
before, after = words(sys.argv[1]), words(sys.argv[2])
r = json.loads(open(sys.argv[3]).read().strip().partition(" ")[2][len("RESULT "):])
streams = after["streams_started"] - before["streams_started"]
others = {k: v for k, v in r["status"].items() if k != "200" and v}
if streams == 0 and not others:
    print("  Envoy started no stream to the processor in the run and the run had no response other than 200")
else:
    print("  Envoy started %d streams to the processor in the run; the run had %d responses other than 200%s"
          % (streams, sum(others.values()),
             " (%s)" % ", ".join("%s: %d" % kv for kv in others.items()) if others else ""))
sys.exit(1 if streams else 0)' "$1" "$2" "$3"
}

# adopt_map: step 1, the processor's pods rolled to map orders-adopt under load, nothing attached: the route added to
# the chart's routes with attach=false, so that the processor's routes file names it and its EnvoyExtensionPolicy does
# not target it. In the foreground: with nothing attached, no stream of the route's waits on the pods that are not up
# yet.
adopt_map() {
  local out stats
  echo ""
  echo "-- (rollout, step 1) the processor's pods rolled to map orders-adopt under load: attach=false on the route" \
    "(helm upgrade: the routes file names it; its EnvoyExtensionPolicy does not); orders and payment still without" \
    "Paztport, so neither verifies"
  STEP_VERIFY=none
  step_begin rollout-map "$ROLLOUT_MAP_DURATION" || return 1
  event "the change began: helm upgrade, orders-adopt in the chart's routes, not attached"
  upgraded measure_chart --set 'routes[2].httpRoute=orders-adopt' --set 'routes[2].receiver=orders' \
    --set 'routes[2].attach=false' || return 1
  event "helm upgrade done: the processor's pods rolled"
  out=$(route_filter orders-adopt)
  if [ "$out" != off ]; then
    change_fail "Envoy has a filter on orders-adopt after the map step: its route is ${out:-unreadable}"
    return 1
  fi
  event "the change done"
  step_end || return 1
  echo "  Envoy still serves orders-adopt without the processor's filter"
  stats=$(envoy_extproc_stats)
  case $stats in
    *streams_started=*) ;;
    *)
      echo "error: Envoy's stream count could not be read after the map step" >&2
      return 1
      ;;
  esac
  map_balance "$STEP_ENVOY" "$stats" "$RUN_DIR/$CASE.result" || {
    change_fail "Envoy started a stream to the processor for orders-adopt in the map step, with no filter on the route"
  }
  backends_counters "after mapping"
}

# attach_balance <Envoy's before> <after> <the processor's outcomes> <the run's .result>: that the attachment cost no
# request, as a sum the run's own counts make: the streams Envoy started to the processor in the run (none before the
# attachment, as the route had no filter), against what the processor's pods decided in it (all of them, as the run
# is the only load; the pods rolled in the step before, and not in this one) and the run's 403s. A 403 on this route is
# the processor's refusal, as orders without Paztport refuses nothing; the pods already map the route, so none is
# expected. Fails when the run had a 403; a sum that does not balance with none is printed only.
attach_balance() {
  python3 -c 'import json, sys
def words(text):
    return {k: int(v) for k, v in (w.split("=") for w in text.split())}
before, after, new = words(sys.argv[1]), words(sys.argv[2]), words(sys.argv[3])
r = json.loads(open(sys.argv[4]).read().strip().partition(" ")[2][len("RESULT "):])
streams = after["streams_started"] - before["streams_started"]
decided, refused = sum(new.values()), r["status"].get("403", 0)
print("  Envoy started %d streams to the processor in the run; the processor decided %d of them;"
      " the run had %d 403s: %d + %d = %d" % (streams, decided, refused, decided, refused, decided + refused))
if not refused and streams == decided:
    print("  every stream was decided by the processor'"'"'s pods, which already mapped the route, and none refused")
elif refused and streams == decided + refused:
    print("  so every stream the processor did not decide was answered 403: unexplained by the attach step'"'"'s"
          " design, as the pods that answer already map orders-adopt (old pods are not expected in it)")
else:
    print("  the sum does not balance, so where the difference came from is not shown")
sys.exit(1 if refused else 0)' "$1" "$2" "$3" "$4"
}

# adopt_attach: step 2, the processor attached to the mapped orders-adopt under load: the route's attach set true, in
# a helm upgrade in the background, while Envoy's routes are read until its filter is enabled on the route. The
# upgrade changes no pod template, so the processor's pods must be the same before and after.
adopt_attach() {
  local served=0 outcomes envoy pods after
  echo ""
  echo "-- (rollout, step 2) the processor attached to orders-adopt under load: attach=true on the route (helm" \
    "upgrade: the processor's EnvoyExtensionPolicy then targets it; its pods do not roll); orders and payment still" \
    "without Paztport, so neither verifies"
  STEP_VERIFY=none
  pods=$(processor_pods | LC_ALL=C sort | paste -sd ' ' -)
  [ -n "$pods" ] || {
    echo "error: the processor's pods could not be read before the attach" >&2
    return 1
  }
  step_begin rollout-attach "$ROLLOUT_ATTACH_DURATION" || return 1
  event "the change began: helm upgrade, orders-adopt attached"
  upgraded measure_chart --set 'routes[2].httpRoute=orders-adopt' --set 'routes[2].receiver=orders' \
    --set 'routes[2].attach=true' &
  CHANGE_HELM_PID=$!
  # Read while helm waits: Envoy enables the filter once the EnvoyExtensionPolicy targets the route.
  route_processed orders-adopt || served=1
  wait "$CHANGE_HELM_PID" || { CHANGE_HELM_PID=""; return 1; }
  CHANGE_HELM_PID=""
  event "helm upgrade done"
  after=$(processor_pods | LC_ALL=C sort | paste -sd ' ' -)
  [ -n "$after" ] || {
    echo "error: the processor's pods could not be read after the attach" >&2
    return 1
  }
  if [ "$after" != "$pods" ]; then
    change_fail "the attach rolled the processor's pods"
    return 1
  fi
  policy_attached envoyextensionpolicy/paztport-processor || return 1
  event "the change done"
  step_end || return 1
  outcomes=$(processor_outcomes) && envoy=$(envoy_extproc_stats) || return 1
  case $envoy in
    *streams_started=*) ;;
    *)
      echo "error: Envoy's stream count could not be read after the attach step" >&2
      return 1
      ;;
  esac
  echo "  the processor's pods, the same before and after, decided since they started: $outcomes"
  attach_balance "$STEP_ENVOY" "$envoy" "$outcomes" "$RUN_DIR/$CASE.result" || {
    change_fail "the attach step had 403s, though the processor's pods already mapped orders-adopt"
  }
  backends_counters "after attaching"
  [ "$served" -eq 0 ]
}

# adopt_enforce: step 3, orders and then payment rolled into enforce under load, their environment kind/backends.yaml's
# again; the backends' traces held to k6's 200s from when both ran it.
adopt_enforce() {
  echo ""
  echo "-- (rollout, step 3) orders and payment rolled straight into enforce under load, the starter back" \
    "(kind/backends.yaml's environment, PAZTPORT_MODE=enforce): orders first, then payment, since a callee in" \
    "enforce refuses every call its caller does not stamp yet"
  STEP_VERIFY=""
  step_begin rollout-enforce "$ROLLOUT_ENFORCE_DURATION" || return 1
  event "the change began: orders rolled into enforce"
  kn set env deployment/orders SPRING_AUTOCONFIGURE_EXCLUDE- SPRING_HTTP_CLIENTS_SSL_BUNDLE- >/dev/null &&
    rolled_out orders || return 1
  event "orders rolled out, in enforce; payment rolled into enforce"
  k apply -f kind/backends.yaml >/dev/null && rolled_out payment && backends_env_matches || return 1
  event "the change done: orders and payment in enforce"
  STEP_VERIFY="from $(event_ms "the change done")"
  step_end || return 1
  STEP_VERIFY=""
  backends_counters "after step 3"
  if backend_reasons 2>/dev/null | grep -q '^orders paztport_response.*reason="CHAIN_MISSING"'; then
    echo "  response checked CHAIN_MISSING: payment's responses while it did not yet run Paztport, unattested. A" \
      "response is content, never refused: an unattested one is recorded as untrusted influence, so this is not a" \
      "request that reached a backend unstamped"
  fi
}

# adopt_bypass: the behavioural line that a request straight to orders, past the Gateway (from the pod checks, over
# mutual TLS with the operator's certificate), is refused CHAIN_MISSING, and orders counted it so. Returns 1 on FAIL.
adopt_bypass() {
  local pods before after out code body verdict
  echo ""
  echo "-- (rollout, after step 3) a request straight to orders, past the Gateway"
  pods=$(backend_pods)
  before=$(backend_reasons) || { change_fail "straight to orders: orders' counters could not be read"; return 1; }
  out=$(kn exec checks -- curl -s -w '\n%{http_code}' --cacert /tls/ca.crt --cert /tls/operator.crt \
    --key /tls/operator.key -X POST -H 'content-type: application/json' -d '{}' https://orders:8080/orders 2>/dev/null)
  code=$(tail -n1 <<<"$out")
  body=$(sed '$d' <<<"$out")
  after=$(orders_counted "$before" 1) || {
    change_fail "straight to orders: orders' counters could not be read"
    return 1
  }
  if [ "$(backend_pods)" != "$pods" ]; then
    change_fail "straight to orders: orders' or payment's pods changed meanwhile, so their counters say nothing"
    return 1
  fi
  verdict=$(orders_decided "$before" "$after" | paste -sd ',' - | sed 's/,/, /g')
  verdict="${verdict:-nothing}"
  if [ "$code" = 403 ] && grep -q CHAIN_MISSING <<<"$body" && [ "$verdict" = "CHAIN_MISSING 1" ]; then
    echo "  PASS straight to orders, past the Gateway: refused, HTTP 403 CHAIN_MISSING; orders counted" \
      "$verdict"
  else
    change_fail "straight to orders, past the Gateway: expected HTTP 403 CHAIN_MISSING and orders counting" \
      "CHAIN_MISSING 1, got HTTP ${code:-none} ($(head -c 200 <<<"$body")), orders counted $verdict"
    return 1
  fi
}

# rollout_undo: orders-adopt deleted first, the backends' environment kind/backends.yaml's again, then change.sh's
# change_undo (the runs stopped, orders-routes and the chart put back, the backends applied and rolled, the edge
# ready). Returns 1 when any of it could not be done, saying which.
rollout_undo() {
  local ok=0
  kn delete httproute orders-adopt --ignore-not-found >/dev/null || {
    echo "error: could not delete the route orders-adopt" >&2
    ok=1
  }
  if ! backends_env_matches 2>/dev/null &&
    kn get deployment orders -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' |
    grep -qw SPRING_AUTOCONFIGURE_EXCLUDE; then
    kn set env deployment/orders SPRING_AUTOCONFIGURE_EXCLUDE- SPRING_HTTP_CLIENTS_SSL_BUNDLE- >/dev/null || ok=1
  fi
  STEP_VARS=()
  STEP_VERIFY=""
  change_undo || ok=1
  backends_env_matches || ok=1
  return "$ok"
}

suite_rollout() {
  local status=0
  echo "== rollout: Paztport adopted under load in the order production takes, on the route orders-adopt: the" \
    "processor mapped to it, then attached, then orders and payment rolled straight into enforce (no audit step:" \
    "audit is for before production)"
  baseline_reset
  CHANGE_FAILS=0
  envoy_admin && change_rate || return 1
  UNDO="rollout_undo"
  STEP_VARS=(HOST="$ADOPT_HOST")
  echo ""
  if adopt_plain && adopt_map && adopt_attach && adopt_enforce; then
    adopt_bypass || true
  else
    echo "error: the rollout stopped; putting back what it changed" >&2
    status=1
  fi
  echo ""
  echo "-- after the rollout: orders-adopt deleted, and the rest put back"
  undo || status=1
  routes_gone orders-adopt || true
  [ "$CHANGE_FAILS" -eq 0 ] || status=1
  return "$status"
}

# --- observe ---

# processor_metrics: every processor pod's /metrics, each line prefixed by its pod's name.
processor_metrics() {
  local pod ip text
  for pod in $(processor_pods); do
    ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
    text=$(kn exec checks -- curl -sf --max-time 10 "http://$ip:9090/metrics" 2>/dev/null) || {
      echo "error: the processor pod $pod did not answer GET /metrics" >&2
      return 1
    }
    printf '%s\n' "$text" | sed "s/^/$pod /"
  done
}

# pods_named <identities>: processor_identity's words cut to each pod's name and uid.
pods_named() {
  tr ' ' '\n' <<<"$1" | cut -d/ -f1,2 | paste -sd ' ' -
}

# processor_identity: each processor pod's name, uid, restarts and start, of those running and not being deleted,
# sorted, on one line: the same before and after means their counters and logs ran through.
processor_identity() {
  local each='{.metadata.name}/{.metadata.uid}/{.status.containerStatuses[0].restartCount}/{.status.startTime}'
  kn get pods -l app.kubernetes.io/name=paztport-processor --field-selector=status.phase=Running \
    -o jsonpath="{range .items[*]}$each {.metadata.deletionTimestamp}{\"\\n\"}{end}" |
    awk 'NF == 1 { print $1 }' | LC_ALL=C sort | paste -sd ' ' -
}

# observe_readings <before> <after>: what the processor counted between two processor_metrics: its outcomes, how
# long stamping took (p50 and p99, from its histogram's buckets as Prometheus' histogram_quantile reads them, and the
# mean), and the bodies' sizes; and how long each pod's material has left.
observe_readings() {
  python3 -c 'import collections, re, sys
def read(text):
    out = collections.defaultdict(float)
    for line in text.splitlines():
        pod, _, rest = line.partition(" ")
        if rest.startswith("#") or not rest.strip():
            continue
        name, _, value = rest.rpartition(" ")
        out[(pod, name)] += float(value)
    return out
before, after = read(sys.argv[1]), read(sys.argv[2])
def added(prefix):
    total = collections.defaultdict(float)
    for (pod, name), v in after.items():
        if name.startswith(prefix):
            total[name] += v - before.get((pod, name), 0)
    return total
def buckets(name):
    got = added(name + "_bucket")
    out = []
    for series, n in got.items():
        le = re.search(r"le=\"([^\"]*)\"", series).group(1)
        out.append((float("inf") if le == "+Inf" else float(le), n))
    return sorted(out)
def quantile(q, bs):
    total = bs[-1][1] if bs else 0
    if not total:
        return None
    rank, lower, below = q * total, 0.0, 0.0
    for le, n in bs:
        if n >= rank:
            if le == float("inf"):
                return lower
            return lower + (le - lower) * (rank - below) / (n - below) if n > below else le
        lower, below = le, n
    return lower
outcomes = added("paztport_edge_requests_total")
print("  the processor decided: " + ", ".join("%s +%d" % (re.search(r"outcome=\"([^\"]*)\"", k).group(1), v)
                                              for k, v in sorted(outcomes.items())))
stamp = buckets("paztport_edge_stamp_seconds")
count, total = added("paztport_edge_stamp_seconds_count"), added("paztport_edge_stamp_seconds_sum")
n, s = sum(count.values()), sum(total.values())
p50, p99 = quantile(0.5, stamp), quantile(0.99, stamp)
print("  stamping (paztport_edge_stamp_seconds, hashing the body and signing), over %d stamped requests: p50 %s, p99"
      " %s, mean %s (p50 and p99 interpolated within the histogram'"'"'s buckets, which run 50 us, 100 us, 250 us,"
      " 500 us, 1 ms and up)" % (n, "%.0f us" % (p50 * 1e6) if p50 is not None else "-",
                                 "%.0f us" % (p99 * 1e6) if p99 is not None else "-",
                                 "%.0f us" % (s / n * 1e6) if n else "-"))
body = buckets("paztport_edge_body_bytes")
bn = sum(added("paztport_edge_body_bytes_count").values())
bs = sum(added("paztport_edge_body_bytes_sum").values())
shown, last = [], 0
for le, c in body:
    if c - last:
        shown.append("%d up to %s" % (c - last, "more" if le == float("inf") else "%d B" % le))
    last = c
print("  the bodies'"'"' sizes (paztport_edge_body_bytes), over %d requests: mean %s; by bucket: %s" % (
    bn, "%.0f B" % (bs / bn) if bn else "-", ", ".join(shown) or "none"))
for (pod, name), v in sorted(after.items()):
    if name == "paztport_edge_material_seconds_left":
        print("  %s: its material has %.0f s left (%.1f days): paztport_edge_material_seconds_left" % (
            pod, v, v / 86400))' "$1" "$2"
}

# observe_load: a discarded warm-up, then a steady run on orders at the suite's rate, DURATION long: the run, whether
# it kept that rate, its window, and what the processor and the backends counted of it.
observe_load() {
  local users line ids m_before m_after r_before r_after
  # k6's users, as the change steps' (change.sh's CHANGE_POOL_SECONDS): the run follows a reset whose rollouts may
  # leave orders' or payment's JVM cold, and a covering run's warm-up then held requests up to 1.8 s (p99 1.4 s), so
  # a pool sized for the warm path would drop requests.
  users=$(held_pool "$CHANGE_RATE_USED" "$CHANGE_POOL_SECONDS")
  echo "-- what the edge and the backends count of a steady run on orders: $CHANGE_RATE_USED/s for $DURATION (k6" \
    "users: $users), after a discarded warm-up of $WARMUP"
  line=$(k6_run observe-warmup TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$CHANGE_RATE_USED" \
    PREALLOC="$users" DURATION="$WARMUP") || return 1
  echo "  warm-up (discarded): $line"
  python3 "$here/measure/summary.py" rate <(echo "warm-up $line") "$CHANGE_RATE_USED"
  ids=$(processor_identity)
  m_before=$(processor_metrics) && r_before=$(backend_reasons) || return 1
  line=$(k6_run observe-load TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$CHANGE_RATE_USED" \
    PREALLOC="$users" DURATION="$DURATION") || return 1
  m_after=$(processor_metrics) && r_after=$(backend_reasons) || return 1
  echo "  the run: $line"
  # A FAIL is counted against the suite with its other pace checks (pace_line).
  run_rated observe-load || true
  window "$RUN_DIR/observe-load.fails"
  if [ "$(processor_identity)" != "$ids" ]; then
    echo "  the processor's pods changed or started again during the run, so what they counted is not all of it"
  fi
  observe_readings "$m_before" "$m_after"
  echo "  what orders and payment counted during the run:"
  reasons_added "$r_before" "$r_after"
}

# edge_key_needles: the edge's key from the material this run used (out/keys/edge.key, which every processor pod
# mounts: the baseline shows it), as "<name>\t<text>" lines in each form a log could hold it: the file's text, its
# DER in standard base64, and the private key itself (the last 32 bytes of the PKCS #8 DER) in base64url, standard
# base64 and hex.
edge_key_needles() {
  python3 -c 'import base64, sys
text = open(sys.argv[1]).read().strip()
der = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
seed = der[-32:]
for name, value in (("the edge key file'"'"'s text", text),
                    ("the edge key'"'"'s DER in base64", base64.b64encode(der).decode()),
                    ("the edge key in base64url", base64.urlsafe_b64encode(seed).decode().rstrip("=")),
                    ("the edge key in base64", base64.b64encode(seed).decode()), ("the edge key in hex", seed.hex())):
    print("%s\t%s" % (name, value))' "$KEYS/edge.key"
}

# pod_logs_copy <namespace> <selector> <file>: every line every container of the pods the selector picks wrote, as
# the kind node keeps their log files (each container's current file and those the kubelet rotated, past 10 MiB, and
# has not yet removed: it keeps five), copied into file, a scratch copy. Prints how many files of how many pods.
pod_logs_copy() {
  local ns="$1" pod uid files=0 pods=0 n
  : >"$3"
  for pod in $(k -n "$ns" get pods -l "$2" -o jsonpath='{.items[*].metadata.name}'); do
    uid=$(k -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
    # shellcheck disable=SC2016 # the scripts run in the node's shell
    n=$(docker exec "$(node_container)" sh -c 'cd "/var/log/pods/$1_$2_$3" && ls -d */* | grep -c .' \
      sh "$ns" "$pod" "$uid") &&
      docker exec "$(node_container)" sh -c 'cd "/var/log/pods/$1_$2_$3" || exit 1
        for f in */*; do case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac || exit 1; done' \
        sh "$ns" "$pod" "$uid" >>"$3" || {
      echo "error: could not read the log files of the pod $pod on the node" >&2
      return 1
    }
    files=$((files + n))
    pods=$((pods + 1))
  done
  echo "$files files of $pods pods"
}

# needle_counts <needles> <file>...: for each needle ("<name>\t<text>" a line), how many lines of the files hold it,
# a name needle (one whose name begins "any") matched without regard to case; "<name>\t<n>" a line.
needle_counts() {
  python3 -c 'import sys
needles = [line.rstrip("\n").split("\t", 1) for line in open(sys.argv[1]) if line.strip()]
lines = []
for path in sys.argv[2:]:
    lines += open(path, errors="replace").read().splitlines()
for name, text in needles:
    if name.startswith("any"):
        n = sum(1 for line in lines if text.lower() in line.lower())
    else:
        n = sum(1 for line in lines if text in line)
    print("%s\t%d" % (name, n))' "$@"
}

# log_scan <needles> <file> <what>: the behavioural line that the file, a scratch copy of the processor's logs, holds
# none of the needles: their names and counts, never their text; a FAIL for a file with no line, as there is then
# nothing to say. Returns 1 on FAIL.
log_scan() {
  local counts found lines
  counts=$(needle_counts "$1" "$2") || { change_fail "$3: the scan could not read its input"; return 1; }
  found=$(awk -F'\t' '$2 > 0 { printf "%s%s (%d lines)", sep, $1, $2; sep = "; " }' <<<"$counts")
  lines=$(grep -c . "$2" || true)
  if [ "${lines:-0}" -eq 0 ]; then
    change_fail "$3: cannot say: no line to scan"
    return 1
  elif [ -z "$found" ]; then
    echo "  PASS $3: none, in $lines lines, of: $(cut -f1 <<<"$counts" | paste -sd ',' - | sed 's/,/, /g')"
  else
    change_fail "$3: expected none in $lines lines, found $found"
    return 1
  fi
}

# markers_answered <what> <status>...: whether the requests that carried the markers were each answered 200, so
# that each reached the processor and was stamped, and the scan of its logs has them to look for; a FAIL, counted,
# when one was not. Returns 1 then.
markers_answered() {
  local what="$1" code bad=""
  shift
  for code in "$@"; do [ "$code" = 200 ] || bad+=" ${code:-none}"; done
  [ -n "$bad" ] || return 0
  change_fail "$what: cannot say: a request that carried a marker was answered${bad}, not 200, so it may never" \
    "have reached the processor"
  return 1
}

# observe_markers: requests that carry markers, and a stamp the processor made, sent through the Gateway; the
# processor's logs scanned for them and for the edge's key; and what Envoy's and the backends' logs hold of them.
observe_markers() {
  local id body_marker header_marker stamp code1 code3 chain proof addr needles="$tmp/observe/needles" copy said names
  local ids_now what
  echo ""
  echo "-- what the logs hold of what requests carried: markers, a stamp the processor made, and the edge's key"
  mkdir -p "$tmp/observe" || return 1
  id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  body_marker="paztport-marker-body-$id"
  header_marker="paztport-marker-header-$id"
  quietly "building edgecheck" go -C "$here/processor" build -o "$tmp/edgecheck" ./cmd/edgecheck
  forward "$NS" svc/paztport-processor 9002
  addr="$FORWARDED"
  code1=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
    -H "x-marker: $header_marker" -d "{\"item\":\"widget\",\"quantity\":1,\"note\":\"$body_marker\"}" \
    "$EDGE/orders" 2>/dev/null)
  echo "  a request through the Gateway with a marker in its body and one in a header of its own (x-marker):" \
    "HTTP $code1"
  stamp=$("$tmp/edgecheck" stamp "$addr" "$KEYS/tls/ca.crt" "$KEYS/tls/edge.crt" "$KEYS/tls/edge.key" "$NS/orders" \
    POST /orders "{\"note\":\"$body_marker\"}" 2>&1) || {
    echo "error: edgecheck stamp did not get a stamp from the processor: $stamp" >&2
    return 1
  }
  chain=$(sed -n 's/^x-path-chain: //p' <<<"$stamp")
  proof=$(sed -n 's/^x-path-proof: //p' <<<"$stamp")
  [ -n "$chain" ] && [ -n "$proof" ] || { echo "error: edgecheck stamp printed no chain or proof" >&2; return 1; }
  names=$(sed -n 's/^\(x-path-[a-z-]*\): .*/\1/p' <<<"$stamp" | paste -sd ' ' -)
  echo "  a stamp the processor made, asked as Envoy asks (edgecheck stamp, with the edge's certificate, through a" \
    "port-forward): the X-Path- headers $names"
  code3=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
    -H "x-path-chain: $chain" -H "x-path-proof: $proof" -d '{}' "$EDGE/orders" 2>/dev/null)
  echo "  that stamp sent through the Gateway as a client's own X-Path- headers (the edge replaces them): HTTP $code3"
  {
    printf 'the body marker\t%s\n' "$body_marker"
    printf 'the header marker\t%s\n' "$header_marker"
    sed -n 's/^\(x-path-[a-z-]*\): \(.*\)/the value of \1\t\2/p' <<<"$stamp"
    edge_key_needles
    printf 'any X-Path- header name\tx-path-\n'
  } >"$needles" || return 1
  sleep 3
  copy="$tmp/observe/processor.log"
  said=$(pod_logs_copy "$NS" app.kubernetes.io/name=paztport-processor "$copy") || return 1
  ids_now=$(processor_identity)
  # By name and uid: a container that started again keeps its earlier log file in its pod's directory.
  if [ "$(pods_named "$ids_now")" != "$(pods_named "$OBSERVE_IDS")" ]; then
    change_fail "the processor's logs hold nothing a request carried, no X-Path- value, and not the edge's key:" \
      "cannot say: the processor's pods changed during the suite (were [$OBSERVE_IDS], are [$ids_now]), so the" \
      "log files of a pod that served the requests may be gone"
    observe_findings "$needles"
    return 1
  fi
  echo "  the scan's input: a scratch copy of every line the processor's containers wrote, from the node's log" \
    "files ($said), each pod the same as when the suite began, before its first request"
  what="the processor's logs hold nothing a request carried, no X-Path- value, and not the edge's key"
  if markers_answered "$what" "$code1" "$code3"; then
    log_scan "$needles" "$copy" "$what" || true
  fi
  observe_findings "$needles"
}

# observe_findings <needles>: what Envoy's log (its access log, and its own lines) and orders' and payment's logs hold
# of the needles, as findings: how many lines hold each, never the text, from scratch copies of their pods' log files
# on the node; and which fields a line of Envoy's access log has.
observe_findings() {
  local d="$tmp/observe" envoy orders payment
  envoy=$(pod_logs_copy "$EG_NS" gateway.envoyproxy.io/owning-gateway-name=edge "$d/envoy.log") &&
    orders=$(pod_logs_copy "$NS" app=orders "$d/orders.log") &&
    payment=$(pod_logs_copy "$NS" app=payment "$d/payment.log") || return 1
  echo "  findings, what other logs hold of the same: lines that hold each, of every line the node keeps of Envoy's" \
    "pod ($envoy; its access log included), orders' ($orders) and payment's ($payment)"
  paste <(needle_counts "$1" "$d/envoy.log") <(needle_counts "$1" "$d/orders.log" | cut -f2) \
    <(needle_counts "$1" "$d/payment.log" | cut -f2) |
    awk -F'\t' -v e="$(grep -c . "$d/envoy.log")" -v o="$(grep -c . "$d/orders.log")" \
      -v p="$(grep -c . "$d/payment.log")" '
      BEGIN { printf "    %-34s %10s %10s %10s\n", "", "Envoy", "orders", "payment"
              printf "    %-34s %10s %10s %10s\n", "(lines read)", e, o, p }
      { printf "    %-34s %10d %10d %10d\n", $1, $2, $3, $4 }'
  echo "  the fields of a line of Envoy's access log (Envoy Gateway's default, as JSON): $(python3 -c 'import json, sys
for line in open(sys.argv[1], errors="replace"):
    _, _, text = line.rstrip("\n").partition(" F ")
    if text.startswith("{") and "response_code" in text:
        print(", ".join(json.loads(text)))
        break' "$d/envoy.log")"
}

suite_observe() {
  local status=0
  echo "== observe: what the edge and the backends count under load, and what the logs hold of what requests carried"
  baseline_reset
  CHANGE_FAILS=0
  UNDO="k6_stop"
  # The pods the suite runs on, once the old ones a reset's roll left draining are gone.
  envoy_admin && change_rate && processor_settled || return 1
  OBSERVE_IDS=$(processor_identity)
  observe_load || status=1
  observe_markers || status=1
  undo
  [ "$CHANGE_FAILS" -eq 0 ] || status=1
  return "$status"
}

# --- gotchas ---

# rewrite_route: the HTTPRoute orders-rewrite, POST /api/orders, its path rewritten to /orders (a URLRewrite filter,
# which Envoy applies as it routes the request: after the processor stamped it), to orders.
rewrite_route() {
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orders-rewrite
  namespace: $NS
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - path: {type: PathPrefix, value: $REWRITE_PATH}
      filters:
        - type: URLRewrite
          urlRewrite:
            path: {type: ReplacePrefixMatch, replacePrefixMatch: /orders}
      backendRefs:
        - {name: orders, port: 8080}
EOF
}

# retry_route: the HTTPRoute orders-retry, POST /orders on the host retry.example, to orders, and its own
# BackendTrafficPolicy, orders-retry-routes: the edge's body limit as its request buffer's, as every route the
# processor maps keeps, and a retry on any 5xx, twice, as an operator might set one. Envoy Gateway v1.10.0's
# BackendTrafficPolicy names it spec.retry.retryOn.triggers, whose values its CRD lists (5xx, gateway-error, reset,
# reset-before-request, connect-failure, retriable-4xx, refused-stream, retriable-status-codes, cancelled,
# deadline-exceeded, internal, resource-exhausted, unavailable), beside spec.retry.retryOn.httpStatusCodes for
# retriable-status-codes, and spec.retry.numRetries.
retry_route() {
  k apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orders-retry
  namespace: $NS
spec:
  parentRefs:
    - name: edge
  hostnames: [$RETRY_HOST]
  rules:
    - matches:
        - path: {type: PathPrefix, value: /orders}
      backendRefs:
        - {name: orders, port: 8080}
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: orders-retry-routes
  namespace: $NS
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: orders-retry}
  retry:
    numRetries: 2
    retryOn:
      triggers: [5xx]
  requestBuffer:
    limit: "$BODY_LIMIT"
EOF
}

# statuses <codes>: the statuses, counted, on one line.
statuses() {
  sort <<<"$1" | uniq -c | awk 'NF == 2 { printf "%s%s %d", sep, $2, $1; sep = ", " } END { print "" }'
}

# gotcha_rewrite: (a) orders-rewrite mapped in the chart, then applied; GOTCHA_PROBES requests on it, and the
# behavioural line that orders refused each one BINDING_MISMATCH.
gotcha_rewrite() {
  local pods before after codes verdict
  echo "-- (a) a route that rewrites the path: orders-rewrite, POST $REWRITE_PATH, rewritten to /orders by Envoy (an" \
    "HTTPRoute URLRewrite filter) as it routes the request to orders; in the chart's routes first (receiver orders;" \
    "helm upgrade), then orders-routes extended to it and the route applied. The processor stamps the request as" \
    "the client sent it, before Envoy rewrites it, so the stamp binds $REWRITE_PATH, and orders is sent /orders"
  CASE=gotcha-rewrite
  : >"$RUN_DIR/$CASE.events"
  upgraded measure_chart --set 'routes[2].httpRoute=orders-rewrite' --set 'routes[2].receiver=orders' || return 1
  routes_policy orders-rewrite && rewrite_route || return 1
  policy_attached envoyextensionpolicy/paztport-processor || return 1
  route_processed orders-rewrite && processor_settled || return 1
  pods=$(backend_pods)
  before=$(backend_reasons) || return 1
  codes=$(edge_posts "$GOTCHA_PROBES" "$REWRITE_PATH")
  after=$(orders_counted "$before" "$GOTCHA_PROBES") || return 1
  if [ "$(backend_pods)" != "$pods" ]; then
    change_fail "orders refuses a request whose path Envoy rewrote after the edge stamped it: orders' or payment's" \
      "pods changed meanwhile, so their counters say nothing"
    return 1
  fi
  verdict=$(python3 -c 'import collections, sys
n, codes = int(sys.argv[1]), collections.Counter(sys.argv[2].split())
added = collections.Counter({r: int(c) for r, c in (line.split() for line in sys.argv[3].splitlines())})
good = (sum(codes.values()) == n and not codes["200"] and added["BINDING_MISMATCH"] == n
        and sum(added.values()) == n)
print("%s answered %s; orders decided %s" % ("PASS" if good else "FAIL",
      ", ".join("%s %d" % kv for kv in sorted(codes.items())) or "nothing",
      ", ".join("%s %d" % kv for kv in sorted(added.items())) or "nothing"))' "$GOTCHA_PROBES" "$codes" \
    "$(orders_decided "$before" "$after")")
  case "$verdict" in
    PASS*) echo "  PASS orders refuses a request whose path Envoy rewrote after the edge stamped it" \
      "(BINDING_MISMATCH): of $GOTCHA_PROBES requests on $REWRITE_PATH, ${verdict#PASS }" ;;
    *) change_fail "orders refuses a request whose path Envoy rewrote after the edge stamped it" \
      "(BINDING_MISMATCH): of $GOTCHA_PROBES requests on $REWRITE_PATH, ${verdict#FAIL }"
      return 1 ;;
  esac
}

# node_second <offset>: the kind node's time, UTC to the second, offset by so many seconds (+1, say).
node_second() {
  docker exec "$(node_container)" date -u -d "${1:-+0} seconds" +%Y-%m-%dT%H:%M:%S
}

# retry_finding <traces>: per rid, what orders did with each time it was sent the request (its traces, by time, and
# which replica): the patterns, counted, as the finding; each rid's own in the case's file.
retry_finding() {
  python3 -c 'import collections, re, sys
by = collections.defaultdict(list)
pods = []
for line in open(sys.argv[1]):
    m = re.search(r"^(\S+) (\S+) .*PAZTPORT_TRACE request rid=(\S+) reason=(\S+)", line)
    if m:
        pod, at, rid, reason = m.groups()
        if pod not in pods:
            pods.append(pod)
        by[rid].append((at, pod, reason))
replica = {pod: "replica %s" % chr(ord("A") + i) for i, pod in enumerate(sorted(pods))}
patterns = collections.Counter()
with open(sys.argv[2], "w") as f:
    for rid, seen in sorted(by.items()):
        seen.sort()
        said = ", then ".join("%s on %s" % (reason, replica[pod]) for _, pod, reason in seen)
        f.write("%s %s\n" % (rid, said))
        oks = {pod for _, pod, reason in seen if reason == "OK"}
        kind = ("served twice, OK on both replicas" if len(oks) > 1 else
                "refused REPLAY on a retry" if any(r == "REPLAY" for _, _, r in seen) else
                "served once, no retry reached orders" if len(seen) == 1 else "other")
        patterns[(kind, ", then ".join(r for _, _, r in seen))] += 1
print("  the finding, per rid, from orders'"'"' traces (%d rids; %s): what orders did each time it was sent it" % (
    len(by), ", ".join("%s is %s" % (replica[p], p) for p in sorted(pods)) or "no pod"))
for (kind, seq), n in sorted(patterns.items(), key=lambda kv: -kv[1]):
    print("    %3d rids  %-40s %s" % (n, kind, seq))
print("  each rid'"'"'s own, by time and replica, in %s" % sys.argv[2].rsplit("/", 1)[1])' "$1" "$2"
}

# gotcha_retry: (b) orders-retry mapped and applied; payment scaled to 0; GOTCHA_REQUESTS requests on the route
# orders, whose retries are confined to what never reached orders (each rid traced once, PASS or FAIL), and as many
# on orders-retry, whose retry on 5xx sends orders the same stamp again (the finding).
gotcha_retry() {
  local since codes oks e_before e_after n
  echo "-- (b) a retry on 5xx: payment scaled to 0, so that orders answers 500 to every order (its call to payment" \
    "fails); first the route orders, whose orders-routes retries only what never reached orders (connect-failure," \
    "refused-stream), then orders-retry (host $RETRY_HOST), mapped in the chart, whose own BackendTrafficPolicy" \
    "orders-retry-routes retries a 5xx twice (retry.retryOn.triggers [5xx], numRetries 2): the retry is the same" \
    "request, the same stamp, sent to orders again"
  CASE=gotcha-retry
  : >"$RUN_DIR/$CASE.events"
  upgraded measure_chart --set 'routes[2].httpRoute=orders-retry' --set 'routes[2].receiver=orders' || return 1
  retry_route && policy_attached backendtrafficpolicy/orders-retry-routes &&
    policy_attached envoyextensionpolicy/paztport-processor || return 1
  route_processed orders-retry && processor_settled || return 1
  echo "  orders-retry answers $(edge_posts 1 /orders "$RETRY_HOST") with payment up"
  kn scale deployment/payment --replicas=0 >/dev/null &&
    kn wait --for=delete pod -l app=payment --timeout=120s >/dev/null 2>&1 || return 1
  n=$(kn get deployment payment -o jsonpath='{.status.replicas}')
  echo "  payment scaled to 0: ${n:-0} pods"
  echo ""
  echo "  on the route orders ($GOTCHA_REQUESTS requests, one at a time):"
  since=$(node_second +1) && sleep 2 || return 1
  e_before=$(envoy_orders_retries orders) || return 1
  codes=$(edge_posts "$GOTCHA_REQUESTS" /orders)
  e_after=$(envoy_orders_retries orders) || return 1
  echo "  answered: $(statuses "$codes")"
  echo "  Envoy counted, of its requests to orders: $(outcomes_added "$e_before" "$e_after")"
  sleep 3
  oks=$(grep -cx 500 <<<"$codes" || true)
  if orders_traces "$since" >"$RUN_DIR/$CASE-orders.traces"; then
    rids_once "$RUN_DIR/$CASE-orders.traces" "$oks" "500s orders answered, each after it verified the request" ||
      CHANGE_FAILS=$((CHANGE_FAILS + 1))
  else
    change_fail "orders served each rid once: orders' log files could not be read (above), so nothing can be said"
  fi
  echo ""
  echo "  on orders-retry ($GOTCHA_REQUESTS requests, one at a time), the finding, no PASS or FAIL:"
  since=$(node_second +1) && sleep 2 || return 1
  e_before=$(envoy_orders_retries orders-retry) || return 1
  codes=$(edge_posts "$GOTCHA_REQUESTS" /orders "$RETRY_HOST")
  e_after=$(envoy_orders_retries orders-retry) || return 1
  echo "  answered: $(statuses "$codes")"
  echo "  Envoy counted, of its requests to orders on orders-retry: $(outcomes_added "$e_before" "$e_after")" \
    "(a retry whose answer Envoy does not retry again, a 403 included, it counts as rq_retry_success)"
  sleep 3
  orders_traces "$since" by-pod >"$RUN_DIR/$CASE-retry.traces" || {
    change_fail "the retry's finding: orders' log files could not be read (above)"
    return 1
  }
  retry_finding "$RUN_DIR/$CASE-retry.traces" "$RUN_DIR/$CASE-retry.rids"
}

# gotchas_undo: the test routes and orders-retry's policy deleted first, payment scaled back to kind/backends.yaml's
# replicas, then change.sh's change_undo (orders-routes and the chart put back, the backends applied and rolled, the
# edge ready). Returns 1 when any of it could not be done, saying which.
gotchas_undo() {
  local ok=0
  kn delete httproute orders-rewrite orders-retry --ignore-not-found >/dev/null &&
    kn delete backendtrafficpolicy orders-retry-routes --ignore-not-found >/dev/null || {
    echo "error: could not delete the routes orders-rewrite and orders-retry, or orders-retry-routes" >&2
    ok=1
  }
  backends_replicas_back >/dev/null || { echo "error: could not scale payment back" >&2; ok=1; }
  change_undo || ok=1
  return "$ok"
}

suite_gotchas() {
  local status=0
  echo "== gotchas: a route that rewrites the path after the edge stamped it, and a retry that sends orders the same" \
    "stamp twice"
  baseline_reset
  CHANGE_FAILS=0
  envoy_admin || return 1
  UNDO="gotchas_undo"
  echo ""
  gotcha_rewrite || status=1
  echo ""
  echo "-- (a) undone"
  if gotchas_undo; then
    UNDO="gotchas_undo"
    echo ""
    gotcha_retry || status=1
  else
    echo "error: what (a) changed could not all be put back; skipping (b)" >&2
    status=1
  fi
  echo ""
  echo "-- after the gotchas: the test routes deleted, payment scaled back, and the rest put back"
  undo || status=1
  echo "  payment's replicas: $(kn get deployment payment -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')" \
    "ready"
  routes_gone orders-rewrite orders-retry || true
  [ "$CHANGE_FAILS" -eq 0 ] || status=1
  return "$status"
}
