# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The load suites. measure.sh sources this after common.sh, and runs each suite_<name> it defines.
#
#   load    plain Envoy against Envoy and the processor: the twin routes echo-plain and echo, each with a small and
#           a large body, under VUS users each sending its next request when the last is answered, alternated.
# shellcheck shell=bash

twin_plain() { RUN_VARS=(HOST="$PLAIN_HOST"); }
twin_stamped() { RUN_VARS=(HOST="$ECHO_HOST"); }

# twins_alike: reads Envoy's configuration from its admin port and shows that the twin routes are served by one
# listener's one filter chain, and differ in nothing but the processor's filter being enabled on echo: their
# routes and their clusters are the same once each one's own name is taken out. Prints PASS or FAIL, and each
# route's per-filter configuration. The dumps (listeners, routes and clusters only: no secrets) go to
# $RUN_DIR/config/.
twins_alike() {
  local pod dir="$RUN_DIR/config" resource
  pod=$(k -n "$EG_NS" get pods -l "gateway.envoyproxy.io/owning-gateway-name=edge" \
    -o jsonpath='{.items[0].metadata.name}') || return 1
  forward "$EG_NS" "pod/$pod" 19000
  mkdir -p "$dir"
  for resource in dynamic_listeners dynamic_route_configs dynamic_active_clusters; do
    curl -s -f "http://$FORWARDED/config_dump?resource=$resource" >"$dir/$resource.json" || {
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

# echo_unstamped: the behavioural lines at the end of a suite on the twins: echo saw no request without a stamp,
# and echo-plain none with one.
echo_unstamped() {
  local counts e_stamped e_unstamped p_stamped p_unstamped ok=0
  counts=$(echo_counts)
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
  return "$ok"
}

suite_load() {
  local body
  echo "== load: plain Envoy (echo-plain) against Envoy and the processor (echo)"
  baseline_reset
  twins_alike || return 1
  for body in small large; do
    echo "-- $body body: VUS=$VUS users, each sending its next request when the last is answered," \
      "DURATION=$DURATION a run, WARMUP=$WARMUP, ROUNDS=$ROUNDS"
    alternate "load-$body" plain twin_plain stamped twin_stamped \
      TARGET="$EDGE/orders" BODY="$body" EXECUTOR=vus VUS="$VUS" DURATION="$DURATION" || return 1
  done
  echo_unstamped
}
