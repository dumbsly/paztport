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

# echo_unstamped: the behavioural lines at the end of a suite on the twins: echo's counts could be read from every
# pod; echo saw no request without a stamp, and echo-plain none with one; and, for each twin, echo counted no fewer
# requests than it answered 200 through the Gateway by the tally (k6's runs and the waits' probes, since echo's
# pods started). It may count more: a request it answered whose response never came back as a 200 (a client
# timeout, a reset) is in its count and not in the tally. Returns 1 if any line is FAIL.
echo_unstamped() {
  local counts e_stamped e_unstamped p_stamped p_unstamped ok=0 host counted sent
  if ! counts=$(echo_counts); then
    echo "  FAIL echo's counts: not every echo pod answered with its counts (above), so nothing can be said of them"
    return 1
  fi
  echo "  echo's counts, since its pods started:"
  printf '%s\n' "$counts" | sed 's/^/    /'
  e_stamped=$(sed -n "s/^$ECHO_HOST stamped=\([0-9]*\) .*/\1/p" <<<"$counts")
  e_unstamped=$(sed -n "s/^$ECHO_HOST .*unstamped=\([0-9]*\)$/\1/p" <<<"$counts")
  p_stamped=$(sed -n "s/^$PLAIN_HOST stamped=\([0-9]*\) .*/\1/p" <<<"$counts")
  p_unstamped=$(sed -n "s/^$PLAIN_HOST .*unstamped=\([0-9]*\)$/\1/p" <<<"$counts")
  if [ "${e_stamped:-0}" -gt 0 ] && [ "$e_unstamped" = 0 ]; then
    echo "  PASS echo (the processor's twin): every request it was sent was stamped ($e_stamped), 0 unstamped"
  else
    echo "  FAIL echo (the processor's twin): expected every request stamped, got ${e_stamped:-none} stamped," \
      "${e_unstamped:-none} unstamped"
    ok=1
  fi
  if [ "${p_unstamped:-0}" -gt 0 ] && [ "$p_stamped" = 0 ]; then
    echo "  PASS echo-plain (plain Envoy): no request it was sent was stamped ($p_unstamped unstamped)"
  else
    echo "  FAIL echo-plain (plain Envoy): expected no request stamped, got ${p_stamped:-none} stamped," \
      "${p_unstamped:-none} unstamped"
    ok=1
  fi
  for host in "$ECHO_HOST" "$PLAIN_HOST"; do
    if [ "$(echo_pod_uids)" != "$(cat "$RUN_DIR/echo-pods" 2>/dev/null)" ]; then
      echo "  FAIL $host: echo's pods are not those the tally was kept for, so their counts have lost requests"
      ok=1
      continue
    fi
    if [ "$host" = "$ECHO_HOST" ]; then
      counted=$((${e_stamped:-0} + ${e_unstamped:-0}))
    else
      counted=$((${p_stamped:-0} + ${p_unstamped:-0}))
    fi
    sent=$(echo_sent "$host")
    if [ "$counted" -ge "$sent" ]; then
      echo "  PASS $host: echo counted $counted requests, and answered $sent with a 200 through the Gateway" \
        "($((counted - sent)) more counted than answered)"
    else
      echo "  FAIL $host: echo counted $counted requests, fewer than the $sent it answered with a 200 through the" \
        "Gateway: its counts lost some"
      ok=1
    fi
  done
  return "$ok"
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

# The users k6 holds ready for the ceiling suite's open-model runs: enough for the highest stage at the latencies of
# a stage that is sustained, so that k6 is not what limits it. A stage past the ceiling, whose requests wait up to
# the processor's messageTimeout, runs out of users, and the requests k6 could not start show as dropped.
CEILING_PREALLOC=500

# The users for the saturation runs: more than the ramps', so that requests past what the processor sustains wait
# for it, up to its messageTimeout, and Envoy's answer to them is seen, rather than k6 dropping them unsent for want
# of a free user.
SATURATION_PREALLOC=2000

# ceiling_ramp <route> <host> <replicas> <stage>...: a stepped ramp on the twin route, by its host: a discarded warm-up
# (WARMUP long, at the first stage's rate), then each stage a run of DURATION at its constant offered rate, rising.
# Prints each run, then summary.py's table of the stages and the highest sustained, which it adds to
# $RUN_DIR/ceiling-sustained.
ceiling_ramp() {
  local route="$1" host="$2" replicas="$3" name="$1-r$3" rate line runs
  shift 3
  runs="$RUN_DIR/$name.runs"
  : >"$runs"
  line=$(k6_run "$name-warmup" TARGET="$EDGE/orders" HOST="$host" BODY=small EXECUTOR=rate RATE="$1" \
    PREALLOC="$CEILING_PREALLOC" DURATION="$WARMUP") || return 1
  printf '  warm-up  %6s/s  %s (discarded)\n' "$1" "$line"
  for rate in "$@"; do
    line=$(k6_run "$name-$rate" TARGET="$EDGE/orders" HOST="$host" BODY=small EXECUTOR=rate RATE="$rate" \
      PREALLOC="$CEILING_PREALLOC" DURATION="$DURATION") || return 1
    printf '  stage    %6s/s  %s\n' "$rate" "$line"
    printf '%s %s\n' "$rate" "$line" >>"$runs"
  done
  python3 "$here/measure/summary.py" stages "$runs" "$route" "$replicas" "$RUN_DIR/ceiling-sustained"
}

# sustained <route> <replicas>: the highest stage the ceiling suite saw sustained there, or 0.
sustained() {
  awk -v r="$1" -v n="$2" '$1 == r && $2 == n { s = $3 } END { printf "%d", s }' "$RUN_DIR/ceiling-sustained"
}

# saturation: on one replica, the processor offered 1.5 and 2 times its highest sustained stage, each for
# SATURATION_DURATION: each run, the window of its responses other than 200, what the processor decided in it, what
# Envoy counted of its streams to the processor (a stream that failed, for a full circuit breaker or a timeout, is a
# request Envoy refused with its own 500, failing closed), and the processor's restarts; then echo's counts, which
# show whether any request reached echo unstamped.
saturation() {
  local best factor rate line before after name envoy_before envoy_after
  best=$(sustained echo 1)
  echo "-- saturation: one processor replica, offered 1.5 and 2 times its highest sustained stage ($best/s)," \
    "SATURATION_DURATION=$SATURATION_DURATION a run, from up to $SATURATION_PREALLOC k6 users"
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

# rss_sample <ip> <file> <seconds>: in the background, process_resident_memory_bytes from the processor at ip's
# /metrics, once a second, as "<epoch s> <bytes>" (or "<epoch s> none" when it does not answer) lines in file, until
# $file.stop exists or the seconds have passed. Its pid goes into forwards, which measure.sh kills on exit.
rss_sample() {
  local ip="$1" file="$2" seconds="$3"
  : >"$file"
  (
    for _ in $(seq 1 "$seconds"); do
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
# turn, each step DURATION long: per step, the run, the processor's peak resident memory (sampled once a second
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
  local n stages
  : >"$RUN_DIR/ceiling-sustained"
  for n in 1 2 4; do
    case "$n" in
      1) stages="$CEILING_STAGES_1" ;;
      2) stages="$CEILING_STAGES_2" ;;
      4) stages="$CEILING_STAGES_4" ;;
    esac
    processor_replicas "$n" || return 1
    echo "-- $n processor replica(s): stages of DURATION=$DURATION at $(echo $stages | sed 's/ /, /g') requests a" \
      "second (WARMUP=$WARMUP first, from up to $CEILING_PREALLOC k6 users), on echo, then the same on echo-plain"
    # shellcheck disable=SC2086 # the stages split on space
    ceiling_ramp echo "$ECHO_HOST" "$n" $stages || return 1
    # shellcheck disable=SC2086
    ceiling_ramp echo-plain "$PLAIN_HOST" "$n" $stages || return 1
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
  echo "  the highest sustained stages, in $(basename "$RUN_DIR")/ceiling-sustained" \
    "(route, replicas, requests a second):"
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
    route        paztport: orders, the processor's filter enabled (the routes of its policy: $targets)
                 plain: orders-plain (host $PLAIN_ORDERS_HOST), no ext_proc: Envoy never calls the processor
    orders       paztport: the starter's inbound filter verifies each request (enforce) and refuses what fails;
                 it stamps its call to payment and checks payment's attested response; a trace line and a metric
                 for each
                 plain: no inbound filter, no verification, no stamp on its call, no check of the response
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
# route; then, when the side changed, a discarded warm-up (WARMUP long) on it, since every pod is new. Sets RUN_VARS
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
    EXECUTOR=rate RATE="$EDGE_RATE" PREALLOC="$CEILING_PREALLOC" DURATION="$WARMUP") || return 1
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

# backend_reasons: what orders and payment counted, added up over their pods, read from /actuator/prometheus with
# the operator's certificate: each request they decided, by mode, outcome and reason, and each response orders
# checked, by reason; "<app> <series> <count>" a line.
backend_reasons() {
  local app ip text
  for app in orders payment; do
    for ip in $(kn get pods -l "app=$app" --field-selector=status.phase=Running \
      -o jsonpath='{.items[*].status.podIP}'); do
      text=$(kn exec checks -- curl -sf --max-time 10 --cacert /tls/ca.crt --cert /tls/operator.crt \
        --key /tls/operator.key --resolve "$app:8080:$ip" "https://$app:8080/actuator/prometheus" 2>/dev/null) || {
        echo "error: $app at $ip did not answer /actuator/prometheus" >&2
        return 1
      }
      printf '%s\n' "$text" | grep -E '^paztport_(request|response)_seconds_count\{' | sed "s/^/$app /"
    done
  done | awk '{ n[$1 " " $2] += $3 } END { for (k in n) printf "%s %d\n", k, n[k] }' | LC_ALL=C sort
}

# reasons_added <before> <after>: what backend_reasons counted between two readings, each series that grew, and
# then every reason but OK by name, or that there was none.
reasons_added() {
  python3 -c 'import re, sys
def read(text):
    out = {}
    for line in text.splitlines():
        if line.strip():
            app, series, n = line.split()
            out[(app, series)] = int(n)
    return out
before, after = read(sys.argv[1]), read(sys.argv[2])
bad = []
for (app, series), n in sorted(after.items()):
    added = n - before.get((app, series), 0)
    if not added:
        continue
    labels = dict(re.findall(r"(\w+)=\"([^\"]*)\"", series))
    name = "request" if series.startswith("paztport_request") else "response checked"
    shown = " ".join("%s=%s" % (k, labels[k]) for k in ("mode", "outcome", "reason") if k in labels)
    print("    %-8s %-16s %-40s +%d" % (app, name, shown, added))
    if labels.get("reason", "OK") != "OK":
        bad.append("%s %s %s (+%d)" % (app, name, labels["reason"], added))
print("  reasons other than OK: " + ("; ".join(bad) if bad else "none"))' "$1" "$2"
}

# edge_compare: what differs, orders-plain made, then the two sides alternated at EDGE_RATE, each switch a
# rollout and a discarded warm-up; each run, the medians and spread, what Paztport adds, and whether k6 kept to
# the rate.
edge_compare() {
  echo "-- the whole edge: $EDGE_RATE requests a second offered to each side (from up to $CEILING_PREALLOC k6 users)," \
    "small body, DURATION=$DURATION a run, WARMUP=$WARMUP, ROUNDS=$ROUNDS; each switch a rollout and a discarded" \
    "warm-up"
  edge_differs
  edge_plain_make || return 1
  edge_side without || return 1
  echo "  the environment that differs, as the cluster runs it without Paztport (with it, kind/backends.yaml's):"
  diff <(backends_env file) <(backends_env) | sed -n 's/^</    with:    /p; s/^>/    without: /p'
  alternate edge plain edge_plain paztport edge_paztport TARGET="$EDGE/orders" BODY=small EXECUTOR=rate \
    RATE="$EDGE_RATE" PREALLOC="$CEILING_PREALLOC" DURATION="$DURATION" || return 1
  python3 "$here/measure/summary.py" rate "$RUN_DIR/edge.runs" "$EDGE_RATE"
}

# edge_ramp: with Paztport (the route orders, both backends in enforce), stages past what it sustains, and what
# orders and payment counted meanwhile, every reason but OK by name: a stamp that waited longer than orders'
# maxAgeMs shows here as its own reason.
edge_ramp() {
  local before after
  edge_side with || return 1
  echo "-- the route orders with Paztport: stages of DURATION=$DURATION at $(echo $EDGE_STAGES | sed 's/ /, /g')" \
    "requests a second (WARMUP=$WARMUP first, from up to $CEILING_PREALLOC k6 users)"
  before=$(backend_reasons) || return 1
  # shellcheck disable=SC2086 # the stages split on space
  ceiling_ramp orders "" 2 $EDGE_STAGES || return 1
  after=$(backend_reasons) || return 1
  echo "  what orders and payment counted during the ramp (its warm-up included):"
  reasons_added "$before" "$after"
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
