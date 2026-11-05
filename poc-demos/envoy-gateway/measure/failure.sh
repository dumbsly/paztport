# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The failure suite. measure.sh sources this after common.sh, and runs suite_failure.
#
#   failure  the edge under steady load while the processor fails, in five cases, each a k6 run at a constant
#            offered rate with the fault FAILURE_LEAD seconds into it: on echo, at FAILURE_RATE, one processor
#            container killed; one processor pod slowed, its gRPC port and then the whole pod; every processor
#            replica gone, then two again; the processor rolled; and on the route orders, at FAILURE_ORDERS_RATE,
#            one orders container killed. Each case prints its run, the window and timeline of its responses
#            other than 200, what the processor and Envoy counted, and that nothing reached echo unstamped; the
#            last, orders' traces, each rid once.
#
# Every fault is undone by failure_undo: at the end of the suite, when a case fails, and, through measure.sh's
# finish, on any other exit (an interrupt included) while the cluster is kept.
# shellcheck shell=bash

# The seconds of steady load before each fault, and the faults' own lengths: the delay slow_pod adds, how long only
# the gRPC port is slowed, how long the whole pod stays slowed once readiness has taken it out, and how long every
# replica stays down.
FAILURE_LEAD=10
FAILURE_SLOW_MS=600
FAILURE_SLOW_GRPC=60
FAILURE_SLOW_HOLD=20
FAILURE_DOWN_HOLD=30
# The length of each case's k6 run: its lead, its fault, the time to come back, and a tail of steady load.
FAILURE_KILL_DURATION=60s
FAILURE_SLOW_DURATION=120s
FAILURE_DOWN_DURATION=90s
FAILURE_ROLL_DURATION=90s
FAILURE_ORDERS_DURATION=90s

# The case running now: its name (its files in $RUN_DIR are named after it), and its k6 run's pid.
CASE=""
CASE_PID=""
# The behavioural lines that failed in this suite, so far.
FAILURE_FAILS=0

# failure_rate: sets FAILURE_RATE_USED, the requests a second the cases on echo offer, and prints where it came
# from: FAILURE_RATE when set; else half the median of the ceiling suite's highest sustained stage on echo with two
# processor replicas, when that suite ran in this run (ceiling-sustained); else FAILURE_DEFAULT_RATE.
failure_rate() {
  local median=0
  case "$FAILURE_RATE" in
    "") ;;
    *[!0-9]* | 0)
      echo "error: FAILURE_RATE is $FAILURE_RATE, not a number of requests a second" >&2
      return 1
      ;;
    *)
      FAILURE_RATE_USED="$FAILURE_RATE"
      echo "  the rate on echo: $FAILURE_RATE_USED/s, from FAILURE_RATE"
      return 0
      ;;
  esac
  [ ! -f "$RUN_DIR/ceiling-sustained" ] || median=$(sustained echo 2)
  if [ "${median:-0}" -gt 0 ]; then
    FAILURE_RATE_USED=$((median / 2))
    echo "  the rate on echo: $FAILURE_RATE_USED/s, half the median of the highest stage two processor replicas" \
      "sustained on echo in this run's ceiling suite ($median/s, in ceiling-sustained)"
  else
    FAILURE_RATE_USED="$FAILURE_DEFAULT_RATE"
    echo "  the rate on echo: $FAILURE_RATE_USED/s, FAILURE_DEFAULT_RATE: this run has no two-replica median on" \
      "echo from the ceiling suite"
  fi
}

# event <what>: records that what happened now, by the node's clock, in the case's events.
event() {
  event_at "$(node_ms)" "$*"
}

# event_at <epoch ms> <what>: records that what happened at that time, in the case's events.
event_at() {
  local at="$1"
  shift
  printf '%s %s\n' "$at" "$*" >>"$RUN_DIR/$CASE.events"
}

# case_begin <name> <VAR=value>...: starts the case's k6 run (k6_run, with those settings) in the background, then
# waits until k6's pod is running and FAILURE_LEAD seconds more, so that the fault meets steady load.
case_begin() {
  local phase=""
  CASE="$1"
  shift
  : >"$RUN_DIR/$CASE.events"
  k6_run "$CASE" "$@" >"$tmp/$CASE.line" 2>"$tmp/$CASE.err" &
  CASE_PID=$!
  forwards+=("$CASE_PID")
  for _ in $(seq 1 300); do
    phase=$(kn get pods -l "job-name=k6-$CASE" -o jsonpath='{.items[*].status.phase}' 2>/dev/null)
    [ "$phase" = Running ] && break
    sleep 1
  done
  if [ "$phase" != Running ]; then
    echo "error: the k6 run $CASE did not start (its pod: ${phase:-none})" >&2
    return 1
  fi
  sleep "$FAILURE_LEAD"
}

# case_end: waits for the case's run, then prints it, the window of its responses other than 200, and its timeline.
# Returns 1 when the run failed.
case_end() {
  local status
  wait "$CASE_PID"
  status=$?
  CASE_PID=""
  [ ! -s "$tmp/$CASE.err" ] || sed 's/^/  /' "$tmp/$CASE.err"
  [ "$status" -eq 0 ] || return 1
  printf '  %s\n' "$(cat "$tmp/$CASE.line")"
  window "$RUN_DIR/$CASE.fails"
  python3 "$here/measure/summary.py" timeline "$RUN_DIR/$CASE.fails" "$RUN_DIR/$CASE.events"
}

# event_ms <what>: the time of the case's first event that begins with what, or empty.
event_ms() {
  awk -v w="$1" 'index(substr($0, index($0, " ") + 1), w) == 1 { print $1; exit }' "$RUN_DIR/$CASE.events"
}

# since <from ms> <to ms>: the seconds between the two times, as "12.34".
since() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", (b - a) / 1000 }'
}

# pod_ready <pod>: the pod's Ready condition, True or False, or gone.
pod_ready() {
  local ready
  ready=$(kn get pod "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || ready=gone
  printf '%s' "${ready:-False}"
}

# pod_restarts <pod>: how many times the pod's container has started again.
pod_restarts() {
  kn get pod "$1" -o jsonpath='{.status.containerStatuses[0].restartCount}'
}

# ready_count <selector>: how many of the pods the selector picks are ready and not being deleted.
ready_count() {
  kn get pods -l "$1" -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp} {.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' |
    awk 'NF == 2 && $2 == "True"' | grep -c . || true
}

# until_pod <pod> <True|False> <seconds> <what>: polls the pod's Ready condition, about every half second, until it
# is the one given, and records the event what then. Returns 1, recording nothing, when it is not within seconds.
until_pod() {
  local end=$((SECONDS + $3))
  while [ "$SECONDS" -lt "$end" ]; do
    if [ "$(pod_ready "$1")" = "$2" ]; then
      event "$4"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# until_ready <selector> <n> <restarted pod> <restarts before> <seconds> <what>: polls, about every half second,
# until n pods the selector picks are ready and not being deleted, and the pod named (if any) has started again
# since (more restarts than before); records the event what then, and, on the way, the first time the pod named is
# seen not ready. Returns 1 when that is not within seconds.
until_ready() {
  local end=$(($5 + SECONDS)) seen=""
  while [ "$SECONDS" -lt "$end" ]; do
    if [ -n "$3" ] && [ -z "$seen" ] && [ "$(pod_ready "$3")" != True ]; then
      event "$3 not ready"
      seen=1
    fi
    if [ "$(ready_count "$1")" -eq "$2" ] && { [ -z "$3" ] || [ "$(pod_restarts "$3")" -gt "$4" ]; }; then
      [ -z "$3" ] || [ -n "$seen" ] || event "$3 not seen not ready (polled about every half second)"
      event "$6"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# outcomes_by_pod: for each processor pod running and not being deleted, what it decided, by outcome, since it
# started: "<pod> <restarts> <outcome>=<n>..." a line, or "<pod> <restarts> unread" when it does not answer.
outcomes_by_pod() {
  local pod ip text outcome line
  for pod in $(processor_pods); do
    ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
    line="$pod $(pod_restarts "$pod")"
    if text=$(kn exec checks -- curl -sf --max-time 10 "http://$ip:9090/metrics" 2>/dev/null); then
      for outcome in stamped refused_route refused_material refused_body refused_error; do
        line+=" $outcome=$(metric_sum "$text" "paztport_edge_requests_total{outcome=\"$outcome\"}")"
      done
    else
      line+=" unread"
    fi
    echo "$line"
  done
}

# outcomes_by_pod_added <before> <after>: what each processor pod decided between two readings of outcomes_by_pod.
# A pod in both, its container not started again, shows what it added; a pod that is new, or whose container
# started again, shows all it counted since it started; a pod gone shows that its counts went with it.
outcomes_by_pod_added() {
  python3 -c 'import sys
def read(text):
    out = {}
    for line in text.splitlines():
        if line.strip():
            pod, restarts, *rest = line.split()
            out[pod] = (restarts, None if rest == ["unread"] else dict(w.split("=") for w in rest))
    return out
before, after = read(sys.argv[1]), read(sys.argv[2])
if not after:
    print("    no processor pod is running now")
for pod, (restarts, counts) in sorted(after.items()):
    if counts is None:
        print("    %s: did not answer GET /metrics" % pod)
        continue
    was = before.get(pod)
    if was and was[0] == restarts and was[1] is not None:
        words = ", ".join("%s %+d" % (k, int(v) - int(was[1].get(k, 0))) for k, v in counts.items())
        print("    %s: %s" % (pod, words))
    else:
        why = "its container started again" if was else "a new pod"
        words = ", ".join("%s=%s" % kv for kv in counts.items())
        print("    %s (%s, restarts %s): since it started, %s" % (pod, why, restarts, words))
for pod in sorted(set(before) - set(after)):
    print("    %s: gone; what it decided after the first reading went with it" % pod)' "$1" "$2"
}

# echo_stamped: echo's counts on echo's host, "<stamped> <unstamped>", or nothing when they cannot be read.
echo_stamped() {
  local counts
  counts=$(echo_counts) || return 1
  sed -n "s/^$ECHO_HOST stamped=\\([0-9]*\\) unstamped=\\([0-9]*\\)$/\\1 \\2/p" <<<"$counts"
}

# echo_primed: requests on echo through the Gateway, one at a time, until every echo pod has counted one, for up to
# 50: echo_counts takes a pod that has counted nothing for one that lost its counts, and before any load (on a new
# cluster, say) one may have been sent nothing yet.
echo_primed() {
  for _ in $(seq 1 50); do
    echo_counts >/dev/null 2>&1 && return 0
    edge_status "$ECHO_HOST" >/dev/null
  done
  echo_counts >/dev/null
}

# echo_case <before> <after>: the behavioural line for a case on echo, from two readings of echo_stamped: echo was
# sent no request unstamped between them, by echo's own counts, on the same pods. Returns 1 on FAIL.
echo_case() {
  local s0 u0 s1 u1
  read -r s0 u0 <<<"$1"
  read -r s1 u1 <<<"$2"
  if [ -z "$u0" ] || [ -z "$u1" ]; then
    echo "  FAIL nothing reached echo unstamped during the case: echo's counts could not be read"
  elif [ "$(echo_pod_uids)" != "$(cat "$RUN_DIR/echo-pods" 2>/dev/null)" ] || [ "$s1" -lt "$s0" ]; then
    echo "  FAIL nothing reached echo unstamped during the case: echo's pods started again, and lost their counts"
  elif [ "$u1" -eq "$u0" ]; then
    echo "  PASS nothing reached echo unstamped during the case: echo counted stamped +$((s1 - s0)), unstamped +0"
    return 0
  else
    echo "  FAIL nothing reached echo unstamped during the case: echo counted stamped +$((s1 - s0))," \
      "unstamped +$((u1 - u0))"
  fi
  FAILURE_FAILS=$((FAILURE_FAILS + 1))
  return 1
}

# The readings each case on echo takes before its run and after it: echo's counts, what each processor pod
# decided, and Envoy's counters for the processor.
case_before() {
  ECHO_BEFORE=$(echo_stamped) && OUTCOMES_BEFORE=$(outcomes_by_pod) && ENVOY_BEFORE=$(envoy_extproc_stats)
}

# case_after: the readings again, and what each added: what the processor decided, what Envoy counted (its own
# 500s, for a full circuit breaker, are cluster_rq_active_overflow), and echo's behavioural line.
case_after() {
  local echo_after outcomes envoy
  outcomes=$(outcomes_by_pod) && envoy=$(envoy_extproc_stats) || return 1
  echo_after=$(echo_stamped)
  echo "  the processor decided:"
  outcomes_by_pod_added "$OUTCOMES_BEFORE" "$outcomes"
  echo "  Envoy counted, of its streams to the processor: $(outcomes_added "$ENVOY_BEFORE" "$envoy")"
  echo_case "$ECHO_BEFORE" "$echo_after" || true
}

# echo_run <duration>: the settings of a case's run on echo, for case_begin.
echo_run() {
  echo "TARGET=$EDGE/orders HOST=$ECHO_HOST BODY=small EXECUTOR=rate RATE=$FAILURE_RATE_USED"
  echo "PREALLOC=$(pool "$FAILURE_RATE_USED") DURATION=$1"
}

# failure_kill: one processor container killed (SIGKILL) under load, and the time until both replicas are ready.
failure_kill() {
  local pod restarts at
  pod=$(processor_pods | head -n1)
  echo "-- one processor container killed (SIGKILL): echo offered $FAILURE_RATE_USED/s for" \
    "$FAILURE_KILL_DURATION (k6 users: $(pool "$FAILURE_RATE_USED")), the kill $FAILURE_LEAD s into it"
  case_before || return 1
  restarts=$(pod_restarts "$pod")
  # shellcheck disable=SC2046 # the settings split on space
  case_begin failure-kill $(echo_run "$FAILURE_KILL_DURATION") || return 1
  at=$(kill_container "$pod") || return 1
  event_at "$at" "SIGKILL to the processor's container in $pod"
  until_ready app.kubernetes.io/name=paztport-processor 2 "$pod" "$restarts" 180 "both processor replicas ready" || {
    echo "error: the processor did not have two replicas ready within 180 s of the kill" >&2
    return 1
  }
  case_end || return 1
  echo "  both replicas ready again $(since "$at" "$(event_ms "both processor")") s after the kill"
  case_after
}

# failure_slow: one processor pod's gRPC port slowed, with its probes still answered, then the whole pod, until
# readiness takes it out; then the delay removed.
failure_slow() {
  local pod ip at end code ready probes=0 ok=0 readings=0 ready_seen=0 codes="" out_at unslow_at last
  pod=$(processor_pods | head -n1)
  ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
  echo "-- one processor pod slowed by $FAILURE_SLOW_MS ms (tc netem, from the kind node): its gRPC port (9002) alone" \
    "for $FAILURE_SLOW_GRPC s, then the whole pod until readiness takes it out and $FAILURE_SLOW_HOLD s more; echo" \
    "offered $FAILURE_RATE_USED/s for $FAILURE_SLOW_DURATION (k6 users: $(pool "$FAILURE_RATE_USED"))," \
    "the delay $FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin failure-slow $(echo_run "$FAILURE_SLOW_DURATION") || return 1
  at=$(slow_pod "$pod" "$FAILURE_SLOW_MS" grpc) || return 1
  event_at "$at" "$pod's packets from port 9002 delayed $FAILURE_SLOW_MS ms"
  end=$((SECONDS + FAILURE_SLOW_GRPC))
  while [ "$SECONDS" -lt "$end" ]; do
    code=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$ip:9090/readyz" 2>/dev/null)
    ready=$(pod_ready "$pod")
    probes=$((probes + 1))
    readings=$((readings + 1))
    if [ "$code" = 200 ]; then ok=$((ok + 1)); else codes+=" ${code:-none}"; fi
    if [ "$ready" = True ]; then ready_seen=$((ready_seen + 1)); else event "$pod's Ready condition $ready"; fi
    sleep 3
  done
  at=$(slow_pod "$pod" "$FAILURE_SLOW_MS" all) || return 1
  event_at "$at" "the whole pod $pod's packets delayed $FAILURE_SLOW_MS ms"
  until_pod "$pod" False 60 "readiness took $pod out (Ready False)" || event "$pod: still ready 60 s on"
  sleep "$FAILURE_SLOW_HOLD"
  unslow_at=$(unslow_pod "$pod") || return 1
  event_at "$unslow_at" "the delay removed from $pod"
  until_pod "$pod" True 60 "$pod ready again" || event "$pod: not ready 60 s after the delay was removed"
  case_end || return 1
  echo "  while only port 9002 was slowed: /readyz answered 200 to $ok of $probes probes from the pod checks" \
    "${codes:+(the others:$codes) }and the pod was Ready at $ready_seen of $readings readings"
  out_at=$(event_ms "readiness took")
  last=$(sed -n 's/.*"last":\([0-9]*\).*/\1/p' "$RUN_DIR/$CASE.window")
  if [ -z "$out_at" ]; then
    echo "  readiness did not take the whole slowed pod out within 60 s"
  elif [ -z "$last" ]; then
    echo "  readiness took the whole slowed pod out $(since "$(event_ms "the whole pod")" "$out_at") s after the" \
      "delay; no response other than 200 in the run"
  elif [ "$last" -lt "$unslow_at" ]; then
    echo "  readiness took the whole slowed pod out $(since "$(event_ms "the whole pod")" "$out_at") s after the" \
      "delay; the errors stopped while it was still delayed: the last response other than 200 came" \
      "$(since "$out_at" "$last") s after it was taken out, $(since "$last" "$unslow_at") s before the delay was removed"
  else
    echo "  readiness took the whole slowed pod out $(since "$(event_ms "the whole pod")" "$out_at") s after the" \
      "delay, but the errors went on: the last response other than 200 came $(since "$unslow_at" "$last") s after" \
      "the delay was removed"
  fi
  case_after
}

# failure_down: every processor replica gone (replicas=0) for FAILURE_DOWN_HOLD seconds, then two again: every
# response meanwhile refused with a 5xx, and the time to the first 200.
failure_down() {
  local gone_at back_at seconds first probe_at helm code end e x r from to
  echo "-- every processor replica gone (helm upgrade, replicas=0) for $FAILURE_DOWN_HOLD s, then two again: echo" \
    "offered $FAILURE_RATE_USED/s for $FAILURE_DOWN_DURATION (k6 users: $(pool "$FAILURE_RATE_USED")), the" \
    "upgrade $FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin failure-down $(echo_run "$FAILURE_DOWN_DURATION") || return 1
  event "helm upgrade to 0 processor replicas began"
  measure_chart --set replicas=0 --wait --timeout 5m >/dev/null 2>&1 || {
    echo "error: the processor did not scale to 0 replicas" >&2
    return 1
  }
  end=$((SECONDS + 120))
  while [ -n "$(kn get pods -l app.kubernetes.io/name=paztport-processor -o name)" ] && [ "$SECONDS" -lt "$end" ]; do
    sleep 0.5
  done
  [ -z "$(kn get pods -l app.kubernetes.io/name=paztport-processor -o name)" ] || {
    echo "error: processor pods were still there 120 s after scaling to 0" >&2
    return 1
  }
  event "no processor pod left"
  gone_at=$(event_ms "no processor pod")
  # What Envoy Gateway made of it, a few seconds on: its status for the policy, and the listener's filters.
  sleep 5
  event "the processor's policy: Accepted $(policy_accepted)"
  event "the HTTP filters of Envoy's listener: $(listener_filters)"
  sleep $((FAILURE_DOWN_HOLD - 5))
  event "helm upgrade to 2 processor replicas began"
  back_at=$(event_ms "helm upgrade to 2")
  helm="$tmp/failure-down-helm.log"
  measure_chart --set replicas=2 >"$helm" 2>&1 &
  local helm_pid=$!
  forwards+=("$helm_pid")
  end=$((SECONDS + 180))
  code=""
  while [ "$SECONDS" -lt "$end" ]; do
    code=$(edge_status "$ECHO_HOST")
    [ "$code" = 200 ] && break
    sleep 0.2
  done
  if [ "$code" = 200 ]; then event "the first 200 to a probe from the pod checks"; fi
  wait "$helm_pid" || {
    echo "error: the helm upgrade to two processor replicas failed:" >&2
    tail -n 5 "$helm" >&2
    return 1
  }
  until_ready app.kubernetes.io/name=paztport-processor 2 "" 0 180 "both processor replicas ready" || {
    echo "error: the processor did not have two replicas ready within 180 s" >&2
    return 1
  }
  case_end || return 1
  probe_at=$(event_ms "the first 200 to a probe")
  if [ -n "$probe_at" ]; then
    echo "  the first 200 to a probe came $(since "$back_at" "$probe_at") s after the upgrade to two replicas began"
  else
    echo "  no probe was answered 200 within 180 s of the upgrade to two replicas"
  fi
  first=$(python3 "$here/measure/summary.py" first "$RUN_DIR/$CASE.fails" "$back_at")
  case "$first" in
    none) echo "  k6's run had no 200 after the upgrade to two replicas began" ;;
    *) echo "  k6's first 200 from the upgrade to two replicas on was in the run's second +${first% *} (the" \
      "upgrade began at +${first#* } s; k6 counts by whole seconds)" ;;
  esac
  # The behavioural line: k6's whole seconds while no processor pod existed.
  seconds=$(python3 "$here/measure/summary.py" seconds "$RUN_DIR/$CASE.fails" "$gone_at" "$back_at")
  if [ "$seconds" = none ]; then
    echo "  FAIL every response refused with a 5xx while no processor pod existed: no whole second of the run fell" \
      "between the last pod going and the upgrade to two"
    FAILURE_FAILS=$((FAILURE_FAILS + 1))
  else
    read -r from to e x r <<<"$seconds"
    if [ "$e" -eq 0 ] && [ "$r" -eq 0 ] && [ "$x" -gt 0 ]; then
      echo "  PASS every response refused with a 5xx while no processor pod existed: in the run's seconds +$from to" \
        "+$to, $x responses, every one a 5xx"
    else
      echo "  FAIL every response refused with a 5xx while no processor pod existed: in the run's seconds +$from to" \
        "+$to, $e answered 200, $x a 5xx and $r otherwise"
      FAILURE_FAILS=$((FAILURE_FAILS + 1))
    fi
  fi
  case_after
}

# policy_accepted: the processor's EnvoyExtensionPolicy's Accepted condition on its Gateway: "<status> (<message>)".
policy_accepted() {
  kn get envoyextensionpolicy paztport-processor \
    -o jsonpath='{.status.ancestors[0].conditions[?(@.type=="Accepted")].status} ({.status.ancestors[0].conditions[?(@.type=="Accepted")].message})'
}

# listener_filters: the HTTP filters of Envoy's listener for the Gateway, as its admin port shows them.
listener_filters() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/config_dump?resource=dynamic_listeners" | python3 -c 'import json, sys
names = []
for c in json.load(sys.stdin).get("configs", []):
    listener = (c.get("active_state") or {}).get("listener", {})
    if listener.get("name") != "paztport/edge/http":
        continue
    chains = listener.get("filter_chains", []) + [listener[k] for k in ("default_filter_chain",) if k in listener]
    for chain in chains:
        for f in chain.get("filters", []):
            names += [h["name"] for h in f.get("typed_config", {}).get("http_filters", [])]
print(" ".join(names) or "none")'
}

# failure_roll: kubectl rollout restart of the processor under load: the window and its errors.
failure_roll() {
  local end
  echo "-- the processor rolled (kubectl rollout restart): echo offered $FAILURE_RATE_USED/s for" \
    "$FAILURE_ROLL_DURATION (k6 users: $(pool "$FAILURE_RATE_USED")), the restart $FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin failure-roll $(echo_run "$FAILURE_ROLL_DURATION") || return 1
  event "kubectl rollout restart deployment/paztport-processor"
  kn rollout restart deployment/paztport-processor >/dev/null || return 1
  kn rollout status deployment/paztport-processor --timeout=300s >/dev/null || return 1
  event "the rollout complete: two new replicas ready"
  end=$((SECONDS + 120))
  while [ "$(kn get pods -l app.kubernetes.io/name=paztport-processor -o name | grep -c . || true)" -gt 2 ] &&
    [ "$SECONDS" -lt "$end" ]; do
    sleep 0.5
  done
  if [ "$(kn get pods -l app.kubernetes.io/name=paztport-processor -o name | grep -c . || true)" -gt 2 ]; then
    event "old pods still there 120 s after the rollout"
  else
    event "the old pods gone"
  fi
  case_end || return 1
  case_after
}

# envoy_orders_retries: Envoy's counters for its cluster of the route orders that a killed backend moves:
# connections that failed, requests retried (and the retries that then succeeded, and those over the retry
# budget), requests ended by a reset, and connections orders closed with requests on them; "<name>=<n>" words.
envoy_orders_retries() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/stats" | awk -F': ' '
    $1 ~ /^cluster\.httproute\/paztport\/orders\// && $1 !~ /\.internal\./ &&
      $1 ~ /\.upstream_(cx_connect_fail|rq_retry|rq_retry_success|rq_retry_overflow|rq_rx_reset|cx_destroy_remote_with_active_rq)$/ {
      sub(/^.*\.upstream_/, "", $1); s[$1] += $2 }
    END { for (k in s) printf "%s=%d ", k, s[k] }' | tr ' ' '\n' | LC_ALL=C sort | paste -sd ' ' -
}

# orders_traces <since>: orders' trace lines for the requests it received since the time (UTC, to the second, as
# 2026-01-02T03:04:05), from the log files the kind node keeps for every orders pod running: every container's,
# the one killed included, and the files the kubelet rotated (past 10 MiB) as well as the current one, which is all
# kubectl logs would read. "PAZTPORT_TRACE request rid=<rid> reason=<reason> ..." a line.
orders_traces() {
  local pod uid
  for pod in $(live_pods app=orders); do
    uid=$(kn get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
    # shellcheck disable=SC2016 # the script runs in the node's shell
    docker exec "$(node_container)" sh -c 'cd "/var/log/pods/$1_$2_$3/orders" || exit 1
      for f in *; do case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac; done' sh "$NS" "$pod" "$uid" || return 1
  done | awk -v s="$1" 'substr($1, 1, 19) >= s' | grep -F 'PAZTPORT_TRACE request'
}

# rids_once <traces file> <200s>: the behavioural lines on orders' traces: orders traced each rid once, and its
# traces hold no fewer rids it verified OK than k6 counted 200s (each 200 is a request orders verified, so fewer
# means traces are missing, and the first line would say nothing). Returns 1 if either is FAIL.
rids_once() {
  python3 -c 'import collections, re, sys
rids, reasons = collections.Counter(), collections.Counter()
ok = set()
for line in open(sys.argv[1]):
    m = re.search(r"PAZTPORT_TRACE request rid=(\S+) reason=(\S+)", line)
    if not m:
        continue
    rid, reason = m.groups()
    reasons[reason] += 1
    if rid != "-":
        rids[rid] += 1
        if reason == "OK":
            ok.add(rid)
twice = {rid: n for rid, n in rids.items() if n > 1}
oks = int(sys.argv[2])
print("  orders traced %d requests in the run, by reason: %s; %d without a rid" % (
    sum(reasons.values()), ", ".join("%s %d" % kv for kv in sorted(reasons.items())) or "none",
    sum(1 for line in open(sys.argv[1]) if " rid=- " in line)))
bad = 0
if twice:
    print("  FAIL orders served each rid once: %d rids traced more than once, such as %s" % (
        len(twice), ", ".join("%s (%d times)" % kv for kv in sorted(twice.items())[:5])))
    bad = 1
elif not rids:
    print("  FAIL orders served each rid once: orders traced no rid at all")
    bad = 1
else:
    print("  PASS orders served each rid once: %d rids, none traced twice" % len(rids))
if len(ok) >= oks:
    print("  PASS orders traces cover the run: %d rids verified OK, and k6 counted %d 200s" % (len(ok), oks))
else:
    print("  FAIL orders traces cover the run: %d rids verified OK, fewer than the %d 200s k6 counted, so traces"
          " are missing" % (len(ok), oks))
    bad = 1
sys.exit(bad)' "$1" "$2"
}

# failure_orders: one orders container killed (SIGKILL) under load on the route orders: the requests that fail
# (those orders held when it died; a new connection refused is retried by the route's connect-failure retry), and
# orders' traces, each rid served once.
failure_orders() {
  local pod restarts at since_time envoy_before envoy_after p_before p_after oks traces
  pod=$(live_pods app=orders | head -n1)
  echo "-- one orders container killed (SIGKILL): the route orders offered $FAILURE_ORDERS_RATE/s for" \
    "$FAILURE_ORDERS_DURATION (k6 users: $(pool "$FAILURE_ORDERS_RATE")), the kill $FAILURE_LEAD s into it; the" \
    "route retries a connection that failed, and nothing that reached orders"
  restarts=$(pod_restarts "$pod")
  envoy_before=$(envoy_orders_retries) && p_before=$(outcomes_by_pod) || return 1
  # From a second before the run, by the node's clock, which the logs' times are on.
  since_time=$(docker exec "$(node_container)" date -u -d '-1 second' +%Y-%m-%dT%H:%M:%S) || return 1
  case_begin failure-orders TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$FAILURE_ORDERS_RATE" \
    PREALLOC="$(pool "$FAILURE_ORDERS_RATE")" DURATION="$FAILURE_ORDERS_DURATION" || return 1
  at=$(kill_container "$pod") || return 1
  event_at "$at" "SIGKILL to orders' container in $pod"
  until_ready app=orders 2 "$pod" "$restarts" 300 "both orders replicas ready" || {
    echo "error: orders did not have two replicas ready within 300 s of the kill" >&2
    return 1
  }
  case_end || return 1
  echo "  both orders replicas ready again $(since "$at" "$(event_ms "both orders")") s after the kill"
  envoy_after=$(envoy_orders_retries) && p_after=$(outcomes_by_pod) || return 1
  echo "  Envoy counted, of its requests to orders: $(outcomes_added "$envoy_before" "$envoy_after")"
  echo "  the processor decided:"
  outcomes_by_pod_added "$p_before" "$p_after"
  traces="$RUN_DIR/failure-orders.traces"
  orders_traces "$since_time" >"$traces"
  oks=$(sed -n 's/.*"200":\([0-9]*\).*/\1/p' "$RUN_DIR/failure-orders.result")
  rids_once "$traces" "${oks:-0}" || FAILURE_FAILS=$((FAILURE_FAILS + 1))
}

# failure_undo: every fault put back: the case's run stopped, no delay on any processor pod, the chart's objects as
# the chart has them (its policy failing closed; a field changed with kubectl, which then owns it, is taken back:
# helm applies server-side, and would otherwise refuse every later upgrade for the conflict), two processor replicas
# ready, and every orders replica ready.
failure_undo() {
  [ -z "$CASE_PID" ] || kill "$CASE_PID" 2>/dev/null
  CASE_PID=""
  kn delete job -l app=k6 --ignore-not-found >/dev/null 2>&1
  netem_clear >/dev/null || echo "error: could not clear the processor pods' delays" >&2
  measure_chart --force-conflicts >/dev/null 2>&1 || echo "error: could not put the processor's chart back" >&2
  [ "$(fail_open)" = false ] || echo "error: the processor's policy has failOpen $(fail_open), not false" >&2
  processor_replicas 2 >/dev/null || echo "error: could not put the processor back to two ready replicas" >&2
  kn rollout status deployment/orders --timeout=300s >/dev/null &&
    kn wait --for=condition=Ready pod -l app=orders --timeout=300s >/dev/null ||
    echo "error: orders' replicas are not all ready" >&2
}

suite_failure() {
  local status=0 step first=1
  echo "== failure: the edge under load while the processor fails, and while orders does"
  baseline_reset
  FAILURE_FAILS=0
  failure_rate && echo_primed || return 1
  echo "  Envoy fails closed: a request whose stream to the processor fails is refused with Envoy's own 500, or 504" \
    "when the processor did not answer within messageTimeout (message_timeouts). Of the 500s, those its circuit" \
    "breaker on the processor's cluster refused (past 1024 at a time) are cluster_rq_active_overflow"
  UNDO="failure_undo"
  for step in failure_kill failure_slow failure_down failure_roll failure_orders; do
    # Each case starts from the baseline: anything the last one left is put back first.
    [ -n "$first" ] || failure_undo
    first=""
    echo ""
    "$step" || {
      echo "error: $step stopped; putting back what it changed and skipping the rest" >&2
      status=1
      break
    }
  done
  undo
  echo "-- after the cases"
  echo_unstamped || status=1
  [ "$FAILURE_FAILS" -eq 0 ] || status=1
  return "$status"
}
