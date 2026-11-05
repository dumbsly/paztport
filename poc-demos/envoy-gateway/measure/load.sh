# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The load suites. measure.sh sources this after common.sh, and runs each suite_<name> it defines.
#
#   load    plain Envoy against Envoy and the processor: the twin routes echo-plain and echo, each with a small body
#           at LOAD_RATE_SMALL requests a second and a large one at LOAD_RATE_LARGE, alternated. Both twins are
#           offered the same rate, well below either one's ceiling, so the difference is the processor's own time
#           per request and not queueing; the ceilings are the ceiling suite's.
#   ceiling what one, two and four processor replicas sustain on echo, against echo-plain at the same stages, written
#           to $RUN_DIR/ceiling-sustained; then, on one replica, past what it sustains (saturation), and its memory
#           with bodies at the limit.
#   edge    the whole edge: orders and payment with Paztport installed (the route orders, the processor, both in
#           enforce mode) against the same images without it (orders-plain, the starter's auto-configuration
#           excluded), alternated at EDGE_RATE, with what differs printed; orders-plain then deleted and shown gone;
#           then the route orders past what it sustains (EDGE_STAGES), with every reason orders and payment counted.
# shellcheck shell=bash

twin_plain() { RUN_VARS=(HOST="$PLAIN_HOST"); }
twin_stamped() { RUN_VARS=(HOST="$ECHO_HOST"); }

# twins_alike: reads Envoy's configuration from its admin port and shows that the twin routes are served by one
# listener's one filter chain, and differ in nothing but the processor's filter being enabled on echo: their
# routes and their clusters are the same once each one's own name is taken out. Prints PASS or FAIL, and each
# route's per-filter configuration. The dumps (listeners, routes and clusters only: no secrets) go to
# $RUN_DIR/config/.
twins_alike() {
  local dir="$RUN_DIR/config" resource
  envoy_admin || return 1
  mkdir -p "$dir"
  for resource in dynamic_listeners dynamic_route_configs dynamic_active_clusters; do
    curl -s -f "http://$ENVOY_ADMIN/config_dump?resource=$resource" >"$dir/$resource.json" || {
      echo "error: no $resource from Envoy's admin port" >&2
      return 1
    }
  done
  python3 - "$dir" "$ECHO_HOST" "$PLAIN_HOST" <<'EOF'
import json, re, sys

d, echo_host, plain_host = sys.argv[1:4]

def configs(name):
    with open("%s/%s.json" % (d, name)) as f:
        return json.load(f).get("configs", [])

# Each twin's own name, wherever it appears (route and cluster names, metadata, hosts), as one word.
def norm(x):
    if isinstance(x, dict):
        return {norm(k): norm(v) for k, v in x.items()}
    if isinstance(x, list):
        return [norm(v) for v in x]
    if isinstance(x, str):
        return re.sub(r"(?<![a-z0-9-])echo(-plain)?(?![a-z0-9-])", "TWIN", x)
    return x

def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append("%s.%s" % (path, k))
            else:
                out += diff(a[k], b[k], "%s.%s" % (path, k))
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, "%s[%d]" % (path, i))
        return out
    return [] if a == b else [path or "."]

problems = []
found = {}
for c in configs("dynamic_route_configs"):
    rc = c.get("route_config", {})
    for vh in rc.get("virtual_hosts", []):
        for host in (echo_host, plain_host):
            if any(dom.split(":")[0] == host for dom in vh.get("domains", [])):
                found.setdefault(host, []).append((rc["name"], vh))
for host in (echo_host, plain_host):
    if len(found.get(host, [])) != 1:
        problems.append("%d virtual hosts for %s, not 1" % (len(found.get(host, [])), host))
if problems:
    print("  FAIL the twins are alike but for the processor: " + "; ".join(problems))
    sys.exit(1)
(rc_echo, vh_echo), (rc_plain, vh_plain) = found[echo_host][0], found[plain_host][0]
if rc_echo != rc_plain:
    problems.append("the twins are in two route configurations, %s and %s" % (rc_echo, rc_plain))
if len(vh_echo.get("routes", [])) != 1 or len(vh_plain.get("routes", [])) != 1:
    problems.append("a twin's virtual host has more than one route")

# The listeners' filter chains (each listed one, and the default) that serve that route configuration.
chains = []
for c in configs("dynamic_listeners"):
    listener = (c.get("active_state") or {}).get("listener", {})
    named = [("filter chain %d" % i, chain) for i, chain in enumerate(listener.get("filter_chains", []))]
    if "default_filter_chain" in listener:
        named.append(("default filter chain", listener["default_filter_chain"]))
    for which, chain in named:
        for f in chain.get("filters", []):
            rds = f.get("typed_config", {}).get("rds", {})
            if rds.get("route_config_name") == rc_echo:
                filters = [h["name"] for h in f["typed_config"].get("http_filters", [])]
                chains.append((listener["name"], which, filters, f["typed_config"].get("http_filters", [])))
if len(chains) != 1:
    problems.append("%d listener filter chains serve %s, not 1" % (len(chains), rc_echo))
else:
    listener_name, which, filters, http_filters = chains[0]
    extproc = [h for h in http_filters if "ext_proc" in h["name"]]
    if not extproc or not all(h.get("disabled") for h in extproc):
        problems.append("the listener's ext_proc filters are not all disabled by default: %s" % [h["name"] for h in extproc])

vhdiff = diff(norm({k: v for k, v in vh_plain.items() if k != "routes"}),
              norm({k: v for k, v in vh_echo.items() if k != "routes"}))
if vhdiff:
    problems.append("the twins' virtual hosts differ in %s" % vhdiff)
route_echo, route_plain = vh_echo["routes"][0], vh_plain["routes"][0]
differs = diff(norm(route_plain), norm(route_echo))
extproc_names = [h["name"] for h in chains[0][3] if "ext_proc" in h["name"]] if len(chains) == 1 else []
want = [".typed_per_filter_config.%s" % n for n in extproc_names]
if sorted(differs) != sorted(want) or not want:
    problems.append("the routes differ in %s, not in the processor's filter alone" % differs)
for name in want:
    tpfc = route_echo.get("typed_per_filter_config", {}).get(name.split(".", 2)[2])
    if tpfc is None or tpfc.get("disabled"):
        problems.append("the processor's filter is not enabled on echo")

clusters = {}
for c in configs("dynamic_active_clusters"):
    cl = c.get("cluster", {})
    clusters[cl.get("name")] = cl
for route, host in ((route_echo, echo_host), (route_plain, plain_host)):
    if route.get("route", {}).get("cluster") not in clusters:
        problems.append("no cluster %s for %s" % (route.get("route", {}).get("cluster"), host))
if not problems:
    cdiff = diff(norm(clusters[route_plain["route"]["cluster"]]), norm(clusters[route_echo["route"]["cluster"]]))
    if cdiff:
        problems.append("the twins' clusters differ in %s" % cdiff)

if problems:
    print("  FAIL the twins are alike but for the processor: " + "; ".join(problems))
    sys.exit(1)
print("  PASS the twins are alike but for the processor: one route configuration (%s), served by the listener %s's"
      " %s, whose HTTP filters are %s; their virtual hosts, routes and clusters are the same but for their names,"
      " and the routes differ only in %s, enabled on echo"
      % (rc_echo, listener_name, which, " ".join(filters), " ".join(n[len(".typed_per_filter_config."):] for n in want)))
for route, host in ((route_plain, plain_host), (route_echo, echo_host)):
    print("  %s typed_per_filter_config: %s" % (host, json.dumps(route.get("typed_per_filter_config", {}), sort_keys=True)))
EOF
}

# The users k6 holds ready for the load suite's open-model runs: many more than the rates need at these latencies,
# so a run that falls behind shows as dropped requests, not as a lower rate.
LOAD_PREALLOC=50

suite_load() {
  local body rate
  echo "== load: plain Envoy (echo-plain) against Envoy and the processor (echo), at the same offered rate"
  baseline_reset
  twins_alike || return 1
  for body in small large; do
    if [ "$body" = small ]; then rate="$LOAD_RATE_SMALL"; else rate="$LOAD_RATE_LARGE"; fi
    echo "-- $body body: $rate requests a second offered to each twin (from up to $LOAD_PREALLOC k6 users)," \
      "DURATION=$DURATION a run, WARMUP=$WARMUP, ROUNDS=$ROUNDS"
    alternate "load-$body" plain twin_plain stamped twin_stamped TARGET="$EDGE/orders" BODY="$body" \
      EXECUTOR=rate RATE="$rate" PREALLOC="$LOAD_PREALLOC" DURATION="$DURATION" || return 1
    python3 "$here/measure/summary.py" rate "$RUN_DIR/load-$body.runs" "$rate"
  done
  echo_unstamped
}

# The users the saturation runs hold: more than the ramps', so that requests past what the processor sustains meet
# the edge's own answer to them (Envoy's circuit breaker on the processor's cluster refuses past 1024 at a time),
# rather than k6 dropping them unsent.
SATURATION_PREALLOC=2000

# ceiling_ramp <route> <host> <replicas> <round> <stage>...: a stepped ramp on the twin route, by its host: a
# discarded warm-up (WARMUP long, at the first stage's rate), then each stage a run of DURATION at its constant
# offered rate, rising. Prints each run, then summary.py's table of the stages and the round's highest sustained
# stage, which it adds to $RUN_DIR/ceiling-rounds (or RAMP_ROUNDS_FILE, when the caller sets it).
ceiling_ramp() {
  local route="$1" host="$2" replicas="$3" round="$4" name="$1-r$3-$4" rate line runs
  shift 4
  runs="$RUN_DIR/$name.runs"
  : >"$runs"
  line=$(k6_run "$name-warmup" TARGET="$EDGE/orders" HOST="$host" BODY=small EXECUTOR=rate RATE="$1" \
    PREALLOC="$(pool "$1")" DURATION="$WARMUP") || return 1
  printf '  warm-up  %6s/s  %s (discarded)\n' "$1" "$line"
  for rate in "$@"; do
    line=$(k6_run "$name-$rate" TARGET="$EDGE/orders" HOST="$host" BODY=small EXECUTOR=rate RATE="$rate" \
      PREALLOC="$(pool "$rate")" DURATION="$DURATION") || return 1
    printf '  stage    %6s/s  %s\n' "$rate" "$line"
    printf '%s %s\n' "$rate" "$line" >>"$runs"
  done
  python3 "$here/measure/summary.py" stages "$runs" "$route" "$replicas" "$round" \
    "${RAMP_ROUNDS_FILE:-$RUN_DIR/ceiling-rounds}"
}

# saturation: on one replica, the processor offered 1.5 and 2 times its highest sustained stage (the median of the
# ceiling's rounds), each for
# SATURATION_DURATION: each run, the window of its responses other than 200, what the processor decided in it, what
# Envoy counted of its streams to the processor (a stream that failed, for a full circuit breaker or a timeout, is a
# request Envoy refused with its own 500, failing closed), and the processor's restarts; then echo's counts, which
# show whether any request reached echo unstamped.
saturation() {
  local best factor rate line before after name envoy_before envoy_after
  best=$(sustained echo 1)
  echo "-- saturation: one processor replica, offered 1.5 and 2 times its highest sustained stage ($best/s)," \
    "SATURATION_DURATION=$SATURATION_DURATION a run, from $SATURATION_PREALLOC k6 users"
  if [ "$best" -eq 0 ]; then
    echo "  no stage was sustained on one replica, so there is nothing to offer more than: skipped"
    return 0
  fi
  for factor in 1.5 2; do
    rate=$(awk -v b="$best" -v f="$factor" 'BEGIN { printf "%d", b * f }')
    name="saturation-$rate"
    before=$(processor_outcomes) || return 1
    envoy_before=$(envoy_extproc_stats) || return 1
    line=$(k6_run "$name" TARGET="$EDGE/orders" HOST="$ECHO_HOST" BODY=small EXECUTOR=rate RATE="$rate" \
      PREALLOC="$SATURATION_PREALLOC" DURATION="$SATURATION_DURATION") || return 1
    after=$(processor_outcomes) || return 1
    envoy_after=$(envoy_extproc_stats) || return 1
    printf '  %sx  %6s/s  %s\n' "$factor" "$rate" "$line"
    window "$RUN_DIR/$name.fails"
    echo "    the processor decided: $(outcomes_added "$before" "$after")"
    echo "    Envoy counted, of its streams to the processor: $(outcomes_added "$envoy_before" "$envoy_after")"
    processor_restarts | sed 's/^/    /'
  done
  echo_unstamped
}

# rss_sample <ip> <file> <samples>: in the background, process_resident_memory_bytes from the processor at ip's
# /metrics, as "<epoch s> <bytes>" (or "<epoch s> none" when it does not answer) lines in file: one reading, then a
# second's sleep, so a little over a second apart (each reading is a kubectl exec, up to a second more when the
# processor is slow), until $file.stop exists or that many samples are taken. Its pid goes into forwards, which
# measure.sh kills on exit.
rss_sample() {
  local ip="$1" file="$2" samples="$3"
  : >"$file"
  (
    for _ in $(seq 1 "$samples"); do
      [ -e "$file.stop" ] && break
      v=$(kn exec checks -- curl -sf --max-time 1 "http://$ip:9090/metrics" 2>/dev/null |
        awk '$1 == "process_resident_memory_bytes" { printf "%d", $2 }')
      echo "$(date +%s) ${v:-none}" >>"$file"
      sleep 1
    done
  ) &
  forwards+=("$!")
  RSS_PID=$!
}

# memory: one processor replica, 1 MiB bodies (the body limit, so admitted and stamped) from MEMORY_VUS users in
# turn, each step DURATION long: per step, the run, the processor's peak resident memory (sampled a little over a
# second apart
# from its /metrics), and its restarts and how it last ended, an OOM kill included. A step in which it restarted
# shows the requests it refused meanwhile in the run's statuses and window.
memory() {
  local vus pod ip line file before after peak samples none limit wait name status
  processor_replicas 1 || return 1
  pod=$(processor_pods)
  limit=$(kn get deployment paztport-processor \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}')
  echo "-- memory: one processor replica ($pod, memory limit $limit), $BODY_LIMIT-byte bodies, users each sending" \
    "the next when the last is answered, DURATION=$DURATION a step"
  for vus in $MEMORY_VUS; do
    name="memory-$vus"
    ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
    before=$(processor_restarts)
    file="$RUN_DIR/$name.rss"
    rm -f "$file.stop"
    wait=$(run_seconds "$DURATION" "") || return 1
    rss_sample "$ip" "$file" $((wait + K6_MARGIN))
    line=$(k6_run "$name" TARGET="$EDGE/orders" HOST="$ECHO_HOST" BODY="$BODY_LIMIT" EXECUTOR=vus VUS="$vus" \
      DURATION="$DURATION")
    status=$?
    touch "$file.stop"
    wait "$RSS_PID" 2>/dev/null
    rm -f "$file.stop"
    [ "$status" -eq 0 ] || return 1
    after=$(processor_restarts)
    peak=$(awk '$2 != "none" && $2 > m { m = $2 } END { printf "%.1f", m / 1048576 }' "$file")
    samples=$(grep -c . "$file" || true)
    none=$(grep -c ' none$' "$file" || true)
    printf '  VUS %-4s %s\n' "$vus" "$line"
    echo "    peak resident memory $peak MiB ($samples samples, $none unanswered); after the step: $after" \
      "(before it: ${before#* })"
    window "$RUN_DIR/$name.fails"
    # A pod that was killed is let come back before the next step.
    kn wait --for=condition=Ready pod -l app.kubernetes.io/name=paztport-processor --timeout=180s >/dev/null || {
      echo "error: the processor did not come back after the step with $vus users" >&2
      return 1
    }
  done
}

# ceiling_steps: the ramps on 1, 2 and 4 processor replicas, saturation after the first, and memory last.
ceiling_steps() {
  local n stages round
  printf '# %s\n' "the median, over CEILING_ROUNDS=$CEILING_ROUNDS rounds of the ceiling suite's ramps, of each" \
    "round's highest sustained stage, in requests a second: <route> <processor replicas> <median>" \
    >"$RUN_DIR/ceiling-sustained"
  : >"$RUN_DIR/ceiling-rounds"
  for n in 1 2 4; do
    case "$n" in
      1) stages="$CEILING_STAGES_1" ;;
      2) stages="$CEILING_STAGES_2" ;;
      4) stages="$CEILING_STAGES_4" ;;
    esac
    processor_replicas "$n" || return 1
    echo "-- $n processor replica(s): CEILING_ROUNDS=$CEILING_ROUNDS rounds of stages of DURATION=$DURATION at" \
      "$(echo $stages | sed 's/ /, /g') requests a second (WARMUP=$WARMUP first; k6 users: the rate x" \
      "$POOL_SECONDS s, at least $CEILING_PREALLOC), on echo and on echo-plain, the one that leads alternating"
    for round in $(seq 1 "$CEILING_ROUNDS"); do
      echo "  round $round"
      if [ $((round % 2)) -eq 1 ]; then
        # shellcheck disable=SC2086 # the stages split on space
        ceiling_ramp echo "$ECHO_HOST" "$n" "$round" $stages &&
          ceiling_ramp echo-plain "$PLAIN_HOST" "$n" "$round" $stages
      else
        # shellcheck disable=SC2086
        ceiling_ramp echo-plain "$PLAIN_HOST" "$n" "$round" $stages &&
          ceiling_ramp echo "$ECHO_HOST" "$n" "$round" $stages
      fi || return 1
    done
    python3 "$here/measure/summary.py" ceiling "$RUN_DIR/ceiling-rounds" "$RUN_DIR/ceiling-sustained" "$n" \
      echo echo-plain || return 1
    [ "$n" != 1 ] || saturation || return 1
  done
  memory
}

suite_ceiling() {
  local status
  echo "== ceiling: what one, two and four processor replicas sustain, against plain Envoy; past it; and memory"
  baseline_reset
  UNDO="ceiling_undo"
  ceiling_steps
  status=$?
  undo
  echo "  the medians of the rounds' highest sustained stages, in $(basename "$RUN_DIR")/ceiling-sustained:"
  sed 's/^/    /' "$RUN_DIR/ceiling-sustained"
  echo_unstamped || status=1
  return "$status"
}

# ceiling_undo: two processor replicas again, the baseline's.
ceiling_undo() {
  processor_replicas 2 >/dev/null || echo "error: could not put the processor back to two replicas" >&2
}

# --- edge: the whole edge, with Paztport installed and without ---
#
# Without Paztport is the application as it would run had Paztport never been installed: the starter's
# auto-configuration excluded on orders and payment (Spring Boot's SPRING_AUTOCONFIGURE_EXCLUDE, payment's own
# exclusion kept beside it), orders given Spring Boot's own mutual TLS client for its call to payment
# (SPRING_HTTP_CLIENTS_SSL_BUNDLE=mesh, the bundle the starter's client presents), and the requests sent on
# orders-plain (kind/orders-plain.yaml), a twin of the route orders that the processor is not attached to. With
# Paztport is the baseline: the route orders, stamped by the processor, and both backends in enforce mode with the
# starter. Each switch is a change to the Deployments' environment and a rollout.

PAZTPORT_AUTOCONFIGURATION=org.paztport.spring.PaztportAutoConfiguration
PLAIN_ORDERS_HOST=orders-plain.example
# Which side the backends run now: with (kind/backends.yaml's) or without.
EDGE_SIDE=with

# edge_differs: what differs between the two sides, and what does not, with what the cluster shows of it.
edge_differs() {
  local targets
  targets=$(kn get envoyextensionpolicy paztport-processor -o jsonpath='{.spec.targetRefs[*].name}')
  cat <<EOT
  What differs, with Paztport installed (paztport) and without (plain):
    route        paztport: orders, the processor's filter enabled (the routes of its policy: $targets):
                 Envoy sends the processor the request's headers, then the whole body, buffered, and the
                 response's headers, from which the processor strips every X-Path- header
                 plain: orders-plain (host $PLAIN_ORDERS_HOST), the processor's filter not enabled (shown below
                 from Envoy's routes): Envoy never calls the processor
    orders       paztport: the starter's inbound filter verifies each request (enforce) and refuses what fails;
                 it stamps its call to payment and checks payment's attested response; it attests its own response
                 (an Ed25519 signature a request), holding the response body until the handler returns; a trace
                 line and a metric for each
                 plain: no inbound filter, no verification, no stamp on its call, no check of payment's response,
                 no attestation of its own
    payment      paztport: the starter's inbound filter verifies each request (enforce) and attests its response;
                 a trace line and a metric for each
                 plain: no inbound filter, no verification, no attestation
    the client   paztport: orders calls payment through the starter's client: the JDK's HttpClient, HTTP/1.1 only,
    orders uses  pooled, presenting the bundle mesh, reading each response whole within its read timeout (30 s)
                 plain: through Spring Boot's own client for the same bundle (SPRING_HTTP_CLIENTS_SSL_BUNDLE=mesh):
                 the JDK's HttpClient through Spring's request factory, HTTP/1.1 with payment (payment's Tomcat
                 offers no HTTP/2), the response read as the handler reads it, no read timeout set
    Host         paztport: the Gateway Service's name; plain: $PLAIN_ORDERS_HOST
  The same on both: the images, mutual TLS on every hop (Envoy to orders by its BackendTLSPolicy, orders to
  payment), Envoy and its listener, the routes' retries and request buffer, replicas and resources.
EOT
}

# edge_plain_make: applies kind/orders-plain.yaml, waits until its BackendTrafficPolicy is accepted, and shows that
# it has orders-routes' retries and request buffer.
edge_plain_make() {
  local want got
  apply_routes kind/orders-plain.yaml >/dev/null && policy_attached backendtrafficpolicy/orders-plain-routes || return 1
  want=$(kn get backendtrafficpolicy orders-routes -o jsonpath='{.spec.retry} {.spec.requestBuffer}')
  got=$(kn get backendtrafficpolicy orders-plain-routes -o jsonpath='{.spec.retry} {.spec.requestBuffer}')
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "error: orders-plain-routes is not orders-routes' settings: [$got], not [$want]" >&2
    return 1
  fi
  echo "  orders-plain made; its BackendTrafficPolicy has orders-routes' retries and request buffer: $got"
  edge_plain_unprocessed
}

# edge_plain_unprocessed: from Envoy's routes (waited for up to 30 s, as Envoy takes a new route a moment late), that
# the processor's filter is enabled on the route orders and not on orders-plain. Prints PASS or FAIL, and each
# route's per-filter configuration; returns 1 on FAIL.
edge_plain_unprocessed() {
  local out=""
  envoy_admin || return 1
  for _ in $(seq 1 30); do
    out=$(curl -sf "http://$ENVOY_ADMIN/config_dump?resource=dynamic_route_configs" | python3 -c 'import json, sys
host = sys.argv[1]
routes = {}
for c in json.load(sys.stdin).get("configs", []):
    for vh in c.get("route_config", {}).get("virtual_hosts", []):
        for r in vh.get("routes", []):
            name = r.get("name", "")
            if name.startswith("httproute/paztport/orders/") or name.startswith("httproute/paztport/orders-plain/"):
                routes.setdefault(name.split("/")[2], []).append(r.get("typed_per_filter_config", {}))
if len(routes.get("orders", [])) != 1 or len(routes.get("orders-plain", [])) != 1:
    print("WAIT %s" % {k: len(v) for k, v in routes.items()})
    sys.exit(0)
def extproc(tpfc):
    return [k for k, v in tpfc.items() if "ext_proc" in k and not v.get("disabled")]
on, plain = extproc(routes["orders"][0]), extproc(routes["orders-plain"][0])
verdict = "PASS" if on and not plain else "FAIL"
print("%s the processor serves orders and not orders-plain: from Envoy'"'"'s routes, its filter is enabled on"
      " orders (%s) and on orders-plain %s" % (verdict, " ".join(on) or "none", " ".join(plain) or "not at all"))
for name in ("orders", "orders-plain"):
    print("  %s typed_per_filter_config: %s" % (name, json.dumps(routes[name][0], sort_keys=True)))' \
      "$PLAIN_ORDERS_HOST")
    case "$out" in WAIT* | "") sleep 1 ;; *) break ;; esac
  done
  case "$out" in
    PASS*) printf '  %s\n' "$out" ;;
    FAIL*) printf '  %s\n' "$out"; return 1 ;;
    *) echo "  FAIL the processor serves orders and not orders-plain: Envoy's routes for them could not be read" \
      "(${out:-no answer})"; return 1 ;;
  esac
}

# edge_plain_remove: deletes orders-plain and its BackendTrafficPolicy, the route first.
edge_plain_remove() {
  kn delete httproute orders-plain --ignore-not-found >/dev/null &&
    kn delete backendtrafficpolicy orders-plain-routes --ignore-not-found >/dev/null
}

# edge_plain_gone: the line that shows orders-plain gone: neither it nor its BackendTrafficPolicy is in the cluster,
# and Envoy serves no virtual host for its host (waited for up to 30 s, as Envoy takes the change a moment late).
# A request for that host now matches the route orders, and is stamped. Returns 1 on FAIL.
edge_plain_gone() {
  local route policy hosts="" dump
  route=$(kn get httproute orders-plain -o name --ignore-not-found 2>&1)
  policy=$(kn get backendtrafficpolicy orders-plain-routes -o name --ignore-not-found 2>&1)
  envoy_admin || return 1
  for _ in $(seq 1 30); do
    dump=$(curl -sf "http://$ENVOY_ADMIN/config_dump?resource=dynamic_route_configs") || dump=""
    hosts=$(printf '%s' "$dump" | python3 -c 'import json, sys
host = sys.argv[1]
for c in json.load(sys.stdin).get("configs", []):
    for vh in c.get("route_config", {}).get("virtual_hosts", []):
        if any(d.split(":")[0] == host for d in vh.get("domains", [])):
            print(vh["name"])' "$PLAIN_ORDERS_HOST" 2>/dev/null) || hosts="(Envoy's routes could not be read)"
    [ -n "$hosts" ] || break
    sleep 1
  done
  if [ -z "$route" ] && [ -z "$policy" ] && [ -z "$hosts" ]; then
    echo "  PASS orders-plain is gone: no HTTPRoute orders-plain, no BackendTrafficPolicy orders-plain-routes, and no" \
      "virtual host for $PLAIN_ORDERS_HOST in Envoy's routes"
  else
    echo "  FAIL orders-plain is gone: expected none, got [${route:-no route}] [${policy:-no policy}]" \
      "[Envoy's virtual hosts for $PLAIN_ORDERS_HOST: ${hosts:-none}]"
    return 1
  fi
}

# edge_side with|without: the backends' environment for that side, rolled out, and Envoy answering 200 on the side's
# route; then, when the side changed, a discarded warm-up (EDGE_WARMUP long) on it, since every pod is new and its
# JVM cold: longer than the runs' WARMUP, so that what follows a rollout is as warm as what follows a run. Sets RUN_VARS
# for alternate: the host of the side's route.
edge_side() {
  local side="$1" exclude host="" code line
  if [ "$side" = without ]; then RUN_VARS=(HOST="$PLAIN_ORDERS_HOST"); host="$PLAIN_ORDERS_HOST"; else RUN_VARS=(); fi
  [ "$side" != "$EDGE_SIDE" ] || return 0
  exclude=$(backends_env file | sed -n 's/^payment SPRING_AUTOCONFIGURE_EXCLUDE=//p')
  if [ "$side" = without ]; then
    kn set env deployment/orders SPRING_AUTOCONFIGURE_EXCLUDE="$PAZTPORT_AUTOCONFIGURATION" \
      SPRING_HTTP_CLIENTS_SSL_BUNDLE=mesh >/dev/null &&
      kn set env deployment/payment SPRING_AUTOCONFIGURE_EXCLUDE="${exclude:+$exclude,}$PAZTPORT_AUTOCONFIGURATION" \
        >/dev/null || return 1
  else
    edge_env_back || return 1
  fi
  EDGE_SIDE="$side"
  kn rollout status deployment/orders --timeout=300s >/dev/null &&
    kn rollout status deployment/payment --timeout=300s >/dev/null || {
    echo "error: orders and payment did not roll out $side Paztport" >&2
    return 1
  }
  for _ in $(seq 1 60); do
    code=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' -X POST ${host:+-H "host: $host"} \
      -H 'content-type: application/json' -d '{}' "$EDGE/orders" 2>/dev/null)
    [ "$code" = 200 ] && break
    sleep 1
  done
  [ "$code" = 200 ] || { echo "error: $side Paztport, the edge answers $code, not 200" >&2; return 1; }
  line=$(k6_run "edge-switch-$side-$(date +%s)" TARGET="$EDGE/orders" ${host:+HOST="$host"} BODY=small \
    EXECUTOR=rate RATE="$EDGE_RATE" PREALLOC="$CEILING_PREALLOC" DURATION="$EDGE_WARMUP") || return 1
  printf '  rolled   %-8s %s (discarded)\n' "$([ "$side" = with ] && echo paztport || echo plain)" "$line"
}
edge_plain() { edge_side without; }
edge_paztport() { edge_side with; }

# edge_env_back: orders and payment back to kind/backends.yaml's environment: the variables the suite added removed,
# payment's own exclusion put back, and the result checked.
edge_env_back() {
  kn set env deployment/orders SPRING_AUTOCONFIGURE_EXCLUDE- SPRING_HTTP_CLIENTS_SSL_BUNDLE- >/dev/null &&
    k apply -f kind/backends.yaml >/dev/null && backends_env_matches
}

# edge_undo: orders-plain deleted and the backends as their file has them, rolled out.
edge_undo() {
  edge_plain_remove || echo "error: could not delete orders-plain" >&2
  if [ "$EDGE_SIDE" != with ] || ! backends_env_matches 2>/dev/null; then
    edge_env_back && kn rollout status deployment/orders --timeout=300s >/dev/null &&
      kn rollout status deployment/payment --timeout=300s >/dev/null ||
      echo "error: could not put orders and payment back as kind/backends.yaml has them" >&2
    EDGE_SIDE=with
  fi
}

# edge_compare: what differs, orders-plain made, then the two sides alternated at EDGE_RATE, each switch a
# rollout and a discarded warm-up (EDGE_WARMUP), and no other warm-up, the first switch's included; each run, the
# medians and spread, what Paztport adds, and whether k6 kept to the rate.
edge_compare() {
  echo "-- the whole edge: $EDGE_RATE requests a second offered to each side ($CEILING_PREALLOC k6 users ready)," \
    "small body, DURATION=$DURATION a run, ROUNDS=$ROUNDS; each switch a rollout and a discarded warm-up of" \
    "EDGE_WARMUP=$EDGE_WARMUP"
  edge_differs
  edge_plain_make || return 1
  edge_side without || return 1
  echo "  the environment that differs, as the cluster runs it without Paztport (with it, kind/backends.yaml's):"
  diff <(backends_env file) <(backends_env) | sed -n 's/^</    with:    /p; s/^>/    without: /p'
  # alternate's own warm-ups would only repeat the switches' (WARMUP=0 leaves them out).
  WARMUP=0 alternate edge plain edge_plain paztport edge_paztport TARGET="$EDGE/orders" BODY=small EXECUTOR=rate \
    RATE="$EDGE_RATE" PREALLOC="$CEILING_PREALLOC" DURATION="$DURATION" || return 1
  python3 "$here/measure/summary.py" rate "$RUN_DIR/edge.runs" "$EDGE_RATE"
}

# The users k6 may start for the overload stage: EDGE_OVERLOAD_RATE x EDGE_OVERLOAD_SECONDS. A stamp older than
# orders' maxAgeMs (5 s) needs requests held about 6 s, so rate x 6 s users (18000 at 3000/s), more than the stage
# holds, and it says so. They are all started before the run, so that none is dropped for want of a user k6 is still
# starting. k6 took about 0.23 MB a user idle here (1.37 GB for 6000) and 2.16 GB for 6000 at 3000/s, past the 2Gi
# the other runs have: the stage's pod has EDGE_OVERLOAD_MEMORY.
EDGE_OVERLOAD_SECONDS=2
EDGE_OVERLOAD_MEMORY=4Gi

# max_age_ms: orders' maxAgeMs, from its environment, or the starter's default (5000).
max_age_ms() {
  backends_env | sed -n 's/^orders PAZTPORT_MAX_AGE_MS=//p' | grep . || echo 5000
}

# envoy_orders_stats: Envoy's counters for its cluster of the route orders: connections and requests over its
# circuit breakers (requests over the connections wait as pending), timed out and retried, as "<name>=<n>" words.
envoy_orders_stats() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/stats" | awk -F': ' '
    $1 ~ /^cluster\.httproute\/paztport\/orders\// && $1 !~ /\.internal\./ &&
      $1 ~ /\.upstream_(cx_overflow|rq_pending_overflow|rq_active_overflow|rq_timeout|rq_retry)$/ {
      sub(/^.*\.upstream_/, "", $1); s[$1] += $2 }
    END { for (k in s) printf "%s=%d ", k, s[k] }' | tr ' ' '\n' | LC_ALL=C sort | paste -sd ' ' -
}

# age_line <longest ms>: whether a stamp older than orders' maxAgeMs could have reached it: a stamp is never older
# at orders than its request is long, so not unless some request took longer.
age_line() {
  local longest="$1" max
  max=$(max_age_ms)
  if awk -v l="$longest" -v m="$max" 'BEGIN { exit !(l < m) }'; then
    echo "  age could not have been tested: the longest request took $longest ms, under orders' maxAgeMs ($max ms)," \
      "and a stamp is never older at orders than its request is long"
  else
    echo "  age could have been tested: the longest request took $longest ms, not under orders' maxAgeMs ($max ms);" \
      "a stamp refused for its age is counted above as EXPIRED"
  fi
}

# edge_ramp: with Paztport (the route orders, both backends in enforce), stages past what it sustains, then one
# overload stage, with what orders and payment counted, every reason but OK by name, their restarts, and whether a
# stamp could have been too old: a ramp whose k6 pool holds only rate x POOL_SECONDS users holds no request near 5 s.
edge_ramp() {
  local before after longest RAMP_ROUNDS_FILE="$RUN_DIR/edge-rounds"
  edge_side with || return 1
  echo "-- the route orders with Paztport: stages of DURATION=$DURATION at $(echo $EDGE_STAGES | sed 's/ /, /g')" \
    "requests a second (WARMUP=$WARMUP first; k6 users: the rate x $POOL_SECONDS s, at least $CEILING_PREALLOC)"
  : >"$RAMP_ROUNDS_FILE"
  before=$(backend_reasons) || return 1
  echo "  orders and payment before: $(backend_restarts)"
  # shellcheck disable=SC2086 # the stages split on space
  ceiling_ramp orders "" 2 1 $EDGE_STAGES || return 1
  after=$(backend_reasons) || return 1
  echo "  what orders and payment counted during the ramp (its warm-up included); after it: $(backend_restarts)"
  reasons_added "$before" "$after"
  longest=$(sed 's/^[0-9]* RESULT //' "$RUN_DIR/orders-r2-1.runs" | python3 -c 'import json, sys
print(max(json.loads(line)["max"] for line in sys.stdin if line.strip()))')
  age_line "$longest"
  edge_overload
}

# edge_overload: the route orders offered EDGE_OVERLOAD_RATE for DURATION, from a pool of k6 users as large as its
# pod holds: what Envoy did with what it could not pass on (its circuit breakers' refusals, counted for the
# processor's cluster and for orders'), what the processor, orders and payment decided, their restarts, and whether
# a stamp could have been too old.
edge_overload() {
  local rate="$EDGE_OVERLOAD_RATE" users want line before after p_before p_after e_before e_after o_before o_after
  users=$(awk -v r="$rate" -v s="$EDGE_OVERLOAD_SECONDS" 'BEGIN { printf "%d", r * s }')
  want=$((rate * 6))
  echo "-- the route orders with Paztport overloaded: $rate requests a second for DURATION=$DURATION, from up to" \
    "$users k6 users"
  echo "  k6's pool: waits past orders' maxAgeMs at $rate/s would need about $want users (the rate x 6 s); the" \
    "stage holds $users (the rate x $EDGE_OVERLOAD_SECONDS s), all started before the run, in a k6 pod of" \
    "$EDGE_OVERLOAD_MEMORY"
  before=$(backend_reasons) && p_before=$(processor_outcomes) && e_before=$(envoy_extproc_stats) &&
    o_before=$(envoy_orders_stats) || return 1
  line=$(K6_MEMORY="$EDGE_OVERLOAD_MEMORY" k6_run edge-overload TARGET="$EDGE/orders" BODY=small EXECUTOR=rate \
    RATE="$rate" PREALLOC="$users" DURATION="$DURATION") || return 1
  after=$(backend_reasons) && p_after=$(processor_outcomes) && e_after=$(envoy_extproc_stats) &&
    o_after=$(envoy_orders_stats) || return 1
  printf '  %6s/s  %s\n' "$rate" "$line"
  window "$RUN_DIR/edge-overload.fails"
  echo "    Envoy counted, of its streams to the processor: $(outcomes_added "$e_before" "$e_after")"
  echo "    Envoy counted, of its requests to orders: $(outcomes_added "$o_before" "$o_after")"
  echo "    the processor decided: $(outcomes_added "$p_before" "$p_after")"
  echo "  what orders and payment counted; after it: $(backend_restarts)"
  reasons_added "$before" "$after"
  age_line "$(printf '%s' "$line" | sed -n 's/.*"max":\([0-9.]*\).*/\1/p')"
}

suite_edge() {
  local status
  echo "== edge: the whole edge, orders and payment with Paztport installed and without"
  baseline_reset
  EDGE_SIDE=with
  UNDO="edge_undo"
  edge_compare
  status=$?
  edge_plain_remove || status=1
  edge_plain_gone || status=1
  [ "$status" -ne 0 ] || edge_ramp || status=1
  undo
  return "$status"
}
