# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The failure suite. measure.sh sources this after common.sh, and runs suite_failure.
#
#   failure  the edge under steady load while the processor fails, each case a k6 run at a constant offered rate
#            with the fault FAILURE_LEAD seconds into it: on echo, at FAILURE_RATE, one processor container killed;
#            one processor pod slowed, its gRPC port (and whether Envoy's health check takes it out) and then
#            the whole pod; every processor replica gone, then two again; the same with Envoy routing to the
#            processor's Service instead of its pods (the EnvoyProxy's routingType Service), after how the load
#            spreads over the replicas under each routing; the processor rolled; and on the route orders, at
#            FAILURE_ORDERS_RATE (unset: common.sh's orders_rate), one orders container killed. Each case prints
#            its run, the window and timeline of its responses other than 200, what the processor and Envoy
#            counted, and that nothing reached echo unstamped; the last, orders' traces, each rid once.
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
# The hold is short on purpose. The chart's liveness probe (every 10 s, a 1 s timeout, three failures) fails every
# probe while the whole pod is slowed, and three failures need at least 20 s of delay. Readiness takes the pod out
# within a few seconds, so those seconds plus this hold stay under 20 s, and the delay alone never has the kubelet
# restart the container.
FAILURE_SLOW_HOLD=10
FAILURE_DOWN_HOLD=30
# The k6 pool of a case is sized for the longest the case can hold a request, not for the healthy path, since a
# request k6 drops for want of a user fails the case's rate line (run_rated). In every case on echo a request can be
# held messageTimeout (500 ms): while its processor pod is killed, drains in a roll, is slowed, or is gone. So its
# pool holds a user for every request in flight were each one held that long and this much more: k6 runs short of
# users, and drops requests unsent, only if the edge holds them longer.
FAILURE_HELD_POOL_SECONDS=0.6
# The case on orders holds requests longer than messageTimeout: while the killed container starts again, the other
# replica takes every request. Sized from a run of this case, at 1000/s with the 0.6 s pool: p99 591 ms, max 1687 ms,
# and 262 requests dropped for want of a user. So its pool holds a user for every request in flight were each one
# held this long, past that max.
FAILURE_ORDERS_POOL_SECONDS=2.5
# The length of each case's k6 run: its lead, its fault, the time to come back, and a tail of steady load.
FAILURE_KILL_DURATION=60s
FAILURE_SLOW_DURATION=120s
FAILURE_DOWN_DURATION=90s
FAILURE_ROLL_DURATION=90s
FAILURE_ORDERS_DURATION=90s

# The case running now: its k6 run's pid, and a helm upgrade's pid while one runs in the background (CASE, its name,
# is common.sh's).
CASE_PID=""
# The rate on the route orders the case there offers (orders_rate).
FAILURE_ORDERS_RATE_USED=""
HELM_PID=""
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

# case_begin <name> <VAR=value>...: starts the case's k6 run (k6_run, with those settings) in the background, then
# waits until k6's pod is running and FAILURE_LEAD seconds more, so that the fault meets steady load.
case_begin() {
  CASE="$1"
  shift
  : >"$RUN_DIR/$CASE.events"
  k6_run "$CASE" "$@" >"$tmp/$CASE.line" 2>"$tmp/$CASE.err" &
  CASE_PID=$!
  forwards+=("$CASE_PID")
  k6_running "$CASE" || return 1
  sleep "$FAILURE_LEAD"
}

# case_end: waits for the case's run, then prints it and whether it kept its rate (run_wait), the window of its
# responses other than 200, and its timeline. Returns 1 when the run failed.
case_end() {
  local pid="$CASE_PID"
  CASE_PID=""
  run_wait "$pid" "$CASE" || return 1
  window "$RUN_DIR/$CASE.fails"
  python3 "$here/measure/summary.py" timeline "$RUN_DIR/$CASE.fails" "$RUN_DIR/$CASE.events"
}

# pod_ready <pod>: the pod's Ready condition, True or False, or gone.
pod_ready() {
  local ready
  ready=$(kn get pod "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || ready=gone
  printf '%s' "${ready:-False}"
}

# pod_restarts <pod>: how many times the pod's container has started again, or nothing when the pod is gone.
pod_restarts() {
  kn get pod "$1" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null
}

# ready_count <selector>: how many of the pods the selector picks are ready and not being deleted.
ready_count() {
  local each='{.metadata.name} {.metadata.deletionTimestamp} {.status.conditions[?(@.type=="Ready")].status}'
  kn get pods -l "$1" -o jsonpath="{range .items[*]}$each{\"\\n\"}{end}" | awk 'NF == 2 && $2 == "True"' |
    grep -c . || true
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
  local end=$(($5 + SECONDS)) seen="" restarts
  while [ "$SECONDS" -lt "$end" ]; do
    if [ -n "$3" ] && [ -z "$seen" ] && [ "$(pod_ready "$3")" != True ]; then
      event "$3 not ready"
      seen=1
    fi
    restarts=""
    [ -z "$3" ] || restarts=$(pod_restarts "$3")
    if [ "$(ready_count "$1")" -eq "$2" ] &&
      { [ -z "$3" ] || { [ -n "$restarts" ] && [ "$restarts" -gt "$4" ]; }; }; then
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
      for outcome in stamped refused_route refused_material refused_body refused_error abandoned; do
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
  elif [ "$u1" -ne "$u0" ]; then
    echo "  FAIL nothing reached echo unstamped during the case: echo counted stamped +$((s1 - s0))," \
      "unstamped +$((u1 - u0))"
  elif [ "$s1" -eq "$s0" ]; then
    echo "  FAIL nothing reached echo unstamped during the case: cannot say: echo counted no request at all in it" \
      "(stamped +0, unstamped +0), so nothing reached it"
  else
    echo "  PASS nothing reached echo unstamped during the case: echo counted stamped +$((s1 - s0)), unstamped +0"
    return 0
  fi
  FAILURE_FAILS=$((FAILURE_FAILS + 1))
  return 1
}

# The readings each case on echo takes before its run and after it: echo's counts, what each processor pod
# decided, and Envoy's counters for the processor.
case_before() {
  ECHO_BEFORE=$(echo_stamped) && OUTCOMES_BEFORE=$(outcomes_by_pod) && ENVOY_BEFORE=$(envoy_extproc_stats)
}

# case_after: the readings again (kept in ECHO_AFTER and ENVOY_AFTER), and what each added: what the processor
# decided, what Envoy counted (its own 500s, for a full circuit breaker, are counted in cluster_rq_active_overflow, the
# harness's label for Envoy's upstream_rq_active_overflow on the processor's cluster), and echo's behavioural line.
case_after() {
  local outcomes
  outcomes=$(outcomes_by_pod) && ENVOY_AFTER=$(envoy_extproc_stats) || return 1
  ECHO_AFTER=$(echo_stamped)
  echo "  the processor decided:"
  outcomes_by_pod_added "$OUTCOMES_BEFORE" "$outcomes"
  echo "  Envoy counted, of its streams to the processor: $(outcomes_added "$ENVOY_BEFORE" "$ENVOY_AFTER")"
  echo_case "$ECHO_BEFORE" "$ECHO_AFTER" || true
}

# echo_run <duration> [users]: the settings of a case's run on echo, for case_begin: k6's pool is the users given,
# or pool's.
echo_run() {
  echo "TARGET=$EDGE/orders HOST=$ECHO_HOST BODY=small EXECUTOR=rate RATE=$FAILURE_RATE_USED"
  echo "PREALLOC=${2:-$(pool "$FAILURE_RATE_USED")} DURATION=$1"
}

# failure_kill: one processor container killed (SIGKILL) under load, and the time until both replicas are ready.
failure_kill() {
  local pod restarts at users
  pod=$(processor_pods | head -n1)
  users=$(held_pool "$FAILURE_RATE_USED" "$FAILURE_HELD_POOL_SECONDS")
  echo "-- one processor container killed (SIGKILL): echo offered $FAILURE_RATE_USED/s for" \
    "$FAILURE_KILL_DURATION (k6 users: $users), the kill $FAILURE_LEAD s into it"
  case_before || return 1
  restarts=$(pod_restarts "$pod")
  # shellcheck disable=SC2046 # the settings split on space
  case_begin failure-kill $(echo_run "$FAILURE_KILL_DURATION" "$users") || return 1
  at=$(kill_container "$pod") || return 1
  event_at "$at" "SIGKILL to the processor's container in $pod"
  until_ready app.kubernetes.io/name=paztport-processor 2 "$pod" "$restarts" 180 "both processor replicas ready" || {
    echo "error: the processor did not have two replicas ready within 180 s of the kill" >&2
    return 1
  }
  case_end || return 1
  echo "  both replicas ready again $(since "$at" "$(event_ms "both processor")") s after the kill (polled about" \
    "every half second, so to within about a second)"
  case_after
}

# failure_slow: one processor pod's gRPC port slowed, with its probes still answered, then the whole pod, until
# readiness takes it out; then the delay removed. Envoy's admin port is read once before the delay, and then every
# pass while only port 9002 is slowed, for whether its active health check has failed the pod's host; when it first
# has, after the delay, is an event, unless it had before.
failure_slow() {
  local pod ip end code ready probes=0 ok=0 readings=0 ready_seen=0 codes="" unslow_at users restarts now ended
  local grpc_at whole_at out_at="" out_by="" polls=0 unread=0 verdict tick=0 before before_by loop_end pass_ms
  pod=$(processor_pods | head -n1)
  ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
  restarts=$(pod_restarts "$pod")
  users=$(held_pool "$FAILURE_RATE_USED" "$FAILURE_HELD_POOL_SECONDS")
  echo "-- one processor pod slowed by $FAILURE_SLOW_MS ms (tc netem, from the kind node): its gRPC port (9002) alone" \
    "for $FAILURE_SLOW_GRPC s, then the whole pod until readiness takes it out and $FAILURE_SLOW_HOLD s more; echo" \
    "offered $FAILURE_RATE_USED/s for $FAILURE_SLOW_DURATION (k6 users: $users, enough for every request to be" \
    "held messageTimeout and more), the delay $FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin failure-slow $(echo_run "$FAILURE_SLOW_DURATION" "$users") || return 1
  # Whether Envoy's check had already failed the host before the delay: if so, a failure read after it is not an
  # ejection by it.
  envoy_admin >/dev/null 2>&1
  before=$(envoy_host_failed "$ip")
  before_by="$ENVOY_ADMIN_POD"
  grpc_at=$(slow_pod "$pod" "$FAILURE_SLOW_MS" grpc) || return 1
  event_at "$grpc_at" "$pod's packets from port 9002 delayed $FAILURE_SLOW_MS ms"
  end=$((SECONDS + FAILURE_SLOW_GRPC))
  while [ "$SECONDS" -lt "$end" ]; do
    # Envoy's health check every pass (about a second), until it first fails the host; the pod's readiness every
    # third. envoy_admin runs in this shell, so that a forward to a new Envoy pod outlives the reading.
    if [ -z "$out_at" ] && [ "$before" != yes ]; then
      envoy_admin >/dev/null 2>&1
      verdict=$(envoy_host_failed "$ip")
      polls=$((polls + 1))
      out_by="$ENVOY_ADMIN_POD"
      case "$verdict" in
        yes)
          out_at=$(node_ms)
          if [ "$before" = unread ]; then
            event_at "$out_at" "Envoy's health check read as failing $pod (its state before the delay was not read)"
          else
            event_at "$out_at" "Envoy's health check took $pod out"
          fi
          ;;
        no) ;;
        *) unread=$((unread + 1)) ;;
      esac
    fi
    if [ $((tick % 3)) -eq 0 ]; then
      code=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$ip:9090/readyz" \
        2>/dev/null)
      ready=$(pod_ready "$pod")
      probes=$((probes + 1))
      readings=$((readings + 1))
      if [ "$code" = 200 ]; then ok=$((ok + 1)); else codes+=" ${code:-none}"; fi
      if [ "$ready" = True ]; then ready_seen=$((ready_seen + 1)); else event "$pod's Ready condition $ready"; fi
    fi
    tick=$((tick + 1))
    sleep 1
  done
  loop_end=$(node_ms)
  pass_ms=$(awk -v a="$grpc_at" -v b="$loop_end" -v n="$tick" 'BEGIN { if (n > 0) printf "%d", (b - a) / n }')
  whole_at=$(slow_pod "$pod" "$FAILURE_SLOW_MS" all) || return 1
  event_at "$whole_at" "the whole pod $pod's packets delayed $FAILURE_SLOW_MS ms"
  until_pod "$pod" False 60 "readiness took $pod out (Ready False)" || event "$pod: still ready 60 s on"
  sleep "$FAILURE_SLOW_HOLD"
  unslow_at=$(unslow_pod "$pod") || return 1
  event_at "$unslow_at" "the delay removed from $pod"
  until_pod "$pod" True 60 "$pod ready again" || event "$pod: not ready 60 s after the delay was removed"
  case_end || return 1
  echo "  while only port 9002 was slowed: /readyz answered 200 to $ok of $probes probes from the pod checks" \
    "${codes:+(the others:$codes) }and the pod was Ready at $ready_seen of $readings readings"
  if [ "$ok" -ne "$probes" ] || [ "$ready_seen" -ne "$readings" ]; then
    echo "  WARN the pod was meant to stay ready while only its gRPC port was slowed, and it did not: the delay" \
      "reached its probes, so what follows is not the case it says"
  fi
  slow_ejection "$grpc_at" "$whole_at" "$out_at" "$out_by" "$polls" "$unread" "$before" "$before_by" "$pass_ms"
  slow_after "$(event_ms "the whole pod")" "$(event_ms "readiness took")" "$unslow_at" "$(event_ms "$pod ready again")"
  now=$(pod_restarts "$pod")
  if [ -z "$now" ]; then
    echo "  the slowed pod $pod is gone"
  elif [ "$now" -gt "$restarts" ]; then
    ended=$(processor_restarts | awk -v p="$pod" '$1 == p { sub(/^last=/, "", $3); sub(/@/, " at ", $3); print $3 }')
    echo "  the slowed pod's container started again during the case: restarts $restarts before it, $now after (it" \
      "last ended $ended)"
  fi
  case_after
}

# slow_ejection <delayed at> <whole pod at> <out at> <Envoy pod> <polls> <unread> <before> <Envoy pod before> <pass ms>:
# whether Envoy's health check took the slowed pod out while only port 9002 was slowed, and when (the third time, in
# epoch ms, empty when it did not; the delay's, the whole pod's); and, from the run's per-second counts (k6's whole
# seconds), the responses other than 200 from the delay to then (or, when it did not, to the whole-pod delay), and from
# then to the whole-pod delay. <before> is what envoy_host_failed read before the delay: with "yes" nothing after it
# is an ejection. Each Envoy pod checks on its own: the readings are of the Envoy pod named, the last one read (the
# fourth), and before the delay the one named by the eighth. The readings were <pass ms> apart on average: the
# 9002-only phase's length over its passes, and what the first failed reading can say of when the host failed.
slow_ejection() {
  local delayed="$1" whole="$2" out="$3" envoy="$4" polls="$5" unread="$6" before="$7" before_by="$8" pass_ms="$9"
  local pass_s note=""
  [ "$before" = no ] || note="; its state before the delay is unknown, so this may not be an ejection by the delay"
  pass_s=$(awk -v m="$pass_ms" 'BEGIN { printf "%.1f", m / 1000 }')
  case "$before" in
    yes)
      echo "  Envoy's health check (read from Envoy pod $before_by) had already failed the slowed pod's host before" \
        "port 9002 was delayed, so nothing that follows is an ejection by the delay"
      slow_window "from the delay on port 9002 to the whole-pod delay" "$delayed" "$whole"
      return 0
      ;;
    no) ;;
    *)
      echo "  Envoy's health check before port 9002 was delayed could not be read, or its cluster held no processor" \
        "host: whether it was already failing is unknown"
      ;;
  esac
  if [ -n "$out" ]; then
    echo "  Envoy's health check (read from Envoy pod $envoy) first read as failing the slowed pod $(since "$delayed" \
      "$out") s after its port 9002 was delayed, at reading $polls (readings $pass_s s apart on average, so it" \
      "failed up to about that long before)$note"
    slow_window "from the delay on port 9002 to that reading" "$delayed" "$out"
    slow_window "from that reading to the whole-pod delay" "$out" "$whole"
  elif [ "$unread" -eq "$polls" ]; then
    echo "  Envoy's admin port could not be read, or held no processor cluster, at any of $polls readings in the" \
      "$FAILURE_SLOW_GRPC s that only port 9002 was slowed: nothing is known of its health check"
    slow_window "from the delay on port 9002 to the whole-pod delay" "$delayed" "$whole"
  elif [ "$unread" -gt 0 ]; then
    echo "  Envoy's health check (read from Envoy pod $envoy) was not seen to take the slowed pod out within the" \
      "$FAILURE_SLOW_GRPC s that only port 9002 was slowed ($polls readings, $unread of them unread)"
    slow_window "from the delay on port 9002 to the whole-pod delay" "$delayed" "$whole"
  else
    echo "  Envoy's health check (read from Envoy pod $envoy) did not take the slowed pod out within the" \
      "$FAILURE_SLOW_GRPC s that only port 9002 was slowed ($polls readings, none unread)"
    slow_window "from the delay on port 9002 to the whole-pod delay" "$delayed" "$whole"
  fi
}

# slow_window <what> <from ms> <to ms>: the responses other than 200 in the run's whole seconds between the two times.
slow_window() {
  local seconds first last e x r
  seconds=$(python3 "$here/measure/summary.py" seconds "$RUN_DIR/$CASE.fails" "$2" "$3")
  if [ -z "$seconds" ]; then
    echo "  $1: the run's per-second counts could not be read for this window"
    return 0
  fi
  if [ "$seconds" = none ]; then
    echo "  $1: no whole second of the run lies within it"
    return 0
  fi
  read -r first last e x r <<<"$seconds"
  echo "  $1: $((x + r)) responses other than 200 of $((e + x + r)), in the run's whole seconds +$first to +$last"
}

# slow_after <slowed at> <out at> <removed at> <ready at>: once the whole pod was slowed (at the first time, in epoch
# ms), when readiness took it out (the second; empty when it did not), and, from the run's per-second counts (k6's
# whole seconds), the last second with a response other than 200 between then and the delay's removal (the third);
# then, on a line of its own, the responses other than 200 from the second the pod was ready again in (the fourth;
# empty when it was not) on.
slow_after() {
  local slowed="$1" out="$2" removed="$3" ready="$4" last after
  if [ -z "$out" ]; then
    echo "  readiness did not take the whole slowed pod out within 60 s"
  else
    last=$(python3 "$here/measure/summary.py" last "$RUN_DIR/$CASE.fails" "$out" "$removed")
    if [ -z "$last" ]; then
      echo "  readiness took the whole slowed pod out $(since "$slowed" "$out") s after the delay; the run's" \
        "per-second counts could not be read for the window from then until the delay was removed"
    elif [ "$last" = none ]; then
      echo "  readiness took the whole slowed pod out $(since "$slowed" "$out") s after the delay; from then until" \
        "the delay was removed, no response other than 200"
    elif [ "${last#* }" -ge "$removed" ]; then
      echo "  readiness took the whole slowed pod out $(since "$slowed" "$out") s after the delay, but the errors" \
        "went on until the delay was removed: the run's second +${last% *}, which holds the removal, had" \
        "responses other than 200"
    else
      echo "  readiness took the whole slowed pod out $(since "$slowed" "$out") s after the delay, and the errors" \
        "stopped within $(since "$out" "${last#* }") s of it: the last second with a response other than 200" \
        "before the delay was removed was the run's +${last% *}, which ended $(since "${last#* }" "$removed") s" \
        "before the removal"
    fi
  fi
  [ -n "$ready" ] || return 0
  after=$(python3 "$here/measure/summary.py" after "$RUN_DIR/$CASE.fails" "$ready")
  if [ -z "$after" ]; then
    echo "  after the pod was ready again: the run's per-second counts could not be read for that window"
  elif [ "$after" = none ]; then
    echo "  after the pod was ready again: no response other than 200"
  else
    echo "  after the pod was ready again, a burst of its own: $(head -n1 <<<"$after" |
      awk '{ printf "%d responses other than 200 in %d second(s)", $1, $2 }'), from the second the pod was ready" \
      "in on: $(sed 1d <<<"$after" | paste -sd ';' - | sed 's/;/; /g')"
  fi
}

# failure_down <name> <routing>: every processor replica gone (replicas=0) for FAILURE_DOWN_HOLD seconds, then two
# again, with Envoy routing to the processor as named (Endpoint or Service): every response meanwhile refused with a
# 5xx; what Envoy Gateway made of the processor's going (its policy's status, the listener's filters, the route's
# answer) and where the 5xx came from; the time to the first 200; and echo's counts at the last pod's going and at
# the upgrade back, which place in time any request that reached echo unstamped.
failure_down() {
  local name="$1" routing="$2" gone_at back_at seconds first probe_at helm code end e x r from to
  local echo_gone echo_back policy filters route fives failed s0 u0 s1 u1 s2 u2 s3 u3 users
  users=$(held_pool "$FAILURE_RATE_USED" "$FAILURE_HELD_POOL_SECONDS")
  echo "-- every processor replica gone (helm upgrade, replicas=0) for $FAILURE_DOWN_HOLD s, then two again, Envoy" \
    "routing to the processor's $(lower "$routing")s: echo offered $FAILURE_RATE_USED/s for" \
    "$FAILURE_DOWN_DURATION (k6 users: $users, enough for every request to be held messageTimeout), the upgrade" \
    "$FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin "$name" $(echo_run "$FAILURE_DOWN_DURATION" "$users") || return 1
  helm="$tmp/$name-helm.log"
  event "helm upgrade to 0 processor replicas began"
  measure_chart --set replicas=0 --wait --timeout 5m >"$helm" 2>&1 || {
    echo "error: the processor did not scale to 0 replicas; helm said:" >&2
    tail -n 5 "$helm" >&2
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
  echo_gone=$(echo_stamped) || return 1
  # What Envoy Gateway made of it, a few seconds on: its status for the policy, the listener's filters, and what
  # Envoy's route for echo does.
  sleep 5
  policy=$(policy_accepted)
  filters=$(listener_filters)
  route=$(echo_route)
  event "the processor's policy: Accepted $policy"
  event "the HTTP filters of Envoy's listener: $filters"
  event "Envoy's route for echo: $route"
  sleep $((FAILURE_DOWN_HOLD - 5))
  echo_back=$(echo_stamped) || return 1
  event "helm upgrade to 2 processor replicas began"
  back_at=$(event_ms "helm upgrade to 2")
  # In the background, so that the probes below time the first 200. Not in forwards: measure.sh's finish must not
  # stop helm half-way; failure_undo waits for it.
  measure_chart --set replicas=2 >"$helm" 2>&1 &
  HELM_PID=$!
  end=$((SECONDS + 180))
  code=""
  while [ "$SECONDS" -lt "$end" ]; do
    code=$(edge_status "$ECHO_HOST")
    [ "$code" = 200 ] && break
    sleep 0.2
  done
  if [ "$code" = 200 ]; then event "the first 200 to a probe from the pod checks"; fi
  wait "$HELM_PID" || {
    HELM_PID=""
    echo "error: the helm upgrade to two processor replicas failed; helm said:" >&2
    tail -n 5 "$helm" >&2
    return 1
  }
  HELM_PID=""
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
    "") echo "  the run's per-second counts could not be read for the window from the upgrade to two replicas on" ;;
    none) echo "  k6's run had no 200 after the upgrade to two replicas began" ;;
    *) echo "  k6's first 200 from the upgrade to two replicas on was in the run's second +${first% *} (the" \
      "upgrade began at +${first#* } s; k6 counts by whole seconds)" ;;
  esac
  # The behavioural line: k6's whole seconds while no processor pod existed.
  seconds=$(python3 "$here/measure/summary.py" seconds "$RUN_DIR/$CASE.fails" "$gone_at" "$back_at")
  if [ -z "$seconds" ]; then
    echo "  FAIL every response refused with a 5xx while no processor pod existed: the run's per-second" \
      "counts could not be read for that window, so nothing can be said"
    FAILURE_FAILS=$((FAILURE_FAILS + 1))
  elif [ "$seconds" = none ]; then
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
  # Who refused them: the filter failing closed counts a failed stream (or a message timeout) for each one; a
  # route Envoy Gateway turned into its own direct response counts none.
  case "$filters $route" in
    *ext_proc*"routed to"*) echo "  while no processor pod existed, the processor's filter stayed in the listener and" \
      "the route stayed routed (the policy: Accepted $policy)" ;;
    *"a direct 500"*) case "$filters" in
      *ext_proc*) echo "  while no processor pod existed, the route served Envoy Gateway's direct 500, the" \
        "processor's filter still in the listener (the policy: Accepted $policy)" ;;
      *) echo "  while no processor pod existed, the filter was removed from the listener and the route served" \
        "Envoy Gateway's direct 500 (the policy: Accepted $policy)" ;;
      esac ;;
    *) echo "  while no processor pod existed: the listener's HTTP filters [$filters], the route for echo [$route]," \
      "the policy Accepted $policy" ;;
  esac
  case_after || return 1
  fives=$(sed -n 's/.*"status":{\(.*\)}}.*/\1/p' "$tmp/$CASE.line" | tr ',' '\n' |
    awk -F: '$1 ~ /"5[0-9][0-9]"/ { n += $2 } END { printf "%d", n }')
  failed=$(stat_added "$ENVOY_BEFORE" "$ENVOY_AFTER" streams_failed message_timeouts)
  if [ "$failed" -ge "$fives" ]; then
    echo "  of the run's $fives 5xx, Envoy's ext_proc filter refused every one, failing closed: it counted $failed" \
      "streams that failed or messages the processor did not answer in time ($((failed - fives)) more than k6's," \
      "the probes' from the pod checks)"
  else
    echo "  of the run's $fives 5xx, Envoy's ext_proc filter refused $failed, failing closed (streams that failed, or" \
      "messages the processor did not answer in time); the other $((fives - failed)) it never handled"
  fi
  read -r s0 u0 <<<"$ECHO_BEFORE"
  read -r s1 u1 <<<"$echo_gone"
  read -r s2 u2 <<<"$echo_back"
  read -r s3 u3 <<<"$ECHO_AFTER"
  if [ -n "$u3" ]; then
    echo "  echo's counts on echo, placed in time: from the case's start to the last pod's going, stamped" \
      "+$((s1 - s0)), unstamped +$((u1 - u0)); while no processor pod existed (to the upgrade to two)," \
      "stamped +$((s2 - s1)), unstamped +$((u2 - u1)); from the upgrade to two to the case's end, stamped" \
      "+$((s3 - s2)), unstamped +$((u3 - u2))"
  fi
}

# stat_added <before> <after> <name>...: what the counters named (in "<name>=<n>" words) added between the two
# readings, together.
stat_added() {
  local a="$1" b="$2"
  shift 2
  awk -v a="$a" -v b="$b" -v names="$*" 'BEGIN {
    n = split(a, x, " "); for (i = 1; i <= n; i++) { split(x[i], kv, "="); before[kv[1]] = kv[2] }
    n = split(b, y, " "); for (i = 1; i <= n; i++) { split(y[i], kv, "="); after[kv[1]] = kv[2] }
    n = split(names, w, " "); for (i = 1; i <= n; i++) s += after[w[i]] - before[w[i]]
    printf "%d", s
  }'
}

# lower <word>: the word in lower case.
lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# echo_route: what Envoy's route for echo does, from its admin port: "routed to <cluster>", or "a direct <status>
# response".
echo_route() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/config_dump?resource=dynamic_route_configs" | python3 -c 'import json, sys
for c in json.load(sys.stdin).get("configs", []):
    for vh in c.get("route_config", {}).get("virtual_hosts", []):
        for r in vh.get("routes", []):
            if r.get("name", "").startswith("httproute/paztport/echo/"):
                if "direct_response" in r:
                    print("a direct %s response" % r["direct_response"].get("status"))
                else:
                    print("routed to %s" % r.get("route", {}).get("cluster"))
                sys.exit(0)
print("none")'
}

# policy_accepted: the processor's EnvoyExtensionPolicy's Accepted condition on its Gateway: "<status> (<message>)".
policy_accepted() {
  local c='.status.ancestors[0].conditions[?(@.type=="Accepted")]'
  kn get envoyextensionpolicy paztport-processor -o jsonpath="{$c.status} ({$c.message})"
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

failure_down_endpoint() { failure_down failure-down Endpoint; }

# failure_roll: kubectl rollout restart of the processor under load: the window and its errors.
failure_roll() {
  local end users
  users=$(held_pool "$FAILURE_RATE_USED" "$FAILURE_HELD_POOL_SECONDS")
  echo "-- the processor rolled (kubectl rollout restart): echo offered $FAILURE_RATE_USED/s for" \
    "$FAILURE_ROLL_DURATION (k6 users: $users), the restart $FAILURE_LEAD s into it"
  case_before || return 1
  # shellcheck disable=SC2046
  case_begin failure-roll $(echo_run "$FAILURE_ROLL_DURATION" "$users") || return 1
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

# envoy_orders_retries [route]: Envoy's counters for its cluster of the route orders (or the route named) that a
# killed backend moves: connections that failed, requests retried (and the retries that then succeeded, and those
# over the retry budget), requests ended by a reset, and connections orders closed with requests on them;
# "<name>=<n>" words.
envoy_orders_retries() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/stats" | awk -F': ' -v c="cluster.httproute/paztport/${1:-orders}/" '
    index($1, c) == 1 && $1 !~ /\.internal\./ &&
      ($1 ~ /\.upstream_(cx_connect_fail|rq_retry|rq_retry_success|rq_retry_overflow|rq_rx_reset)$/ ||
      $1 ~ /\.upstream_cx_destroy_remote_with_active_rq$/) {
      sub(/^.*\.upstream_/, "", $1); s[$1] += $2 }
    END { for (k in s) printf "%s=%d ", k, s[k] }' | tr ' ' '\n' | LC_ALL=C sort | paste -sd ' ' -
}

# rids_once <traces file> <200s> [<what they are>]: the behavioural lines on orders' traces: orders traced each rid
# once, and its traces hold at least as many rids it verified OK as k6 counted 200s (each 200 is a request orders
# verified, so fewer means traces are missing, and the first line would say nothing). It may hold more: a request
# orders verified whose response never came back as a 200 (one it held when it was killed) is traced, and not among
# k6's 200s. With <what they are>, the count is of other responses each of which orders verified, so named.
# Returns 1 if either is FAIL.
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
oks, what = int(sys.argv[2]), sys.argv[3]
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
if not oks:
    print("  FAIL orders traces cover the run: cannot say: there were no %s, so the traces have nothing to be held"
          " to" % what)
    bad = 1
elif len(ok) >= oks:
    print("  PASS orders traces cover the run: %d rids verified OK, at least as many as the %d %s (%d"
          " more: requests orders verified whose response never came back as one)" % (len(ok), oks, what,
                                                                                    len(ok) - oks))
else:
    print("  FAIL orders traces cover the run: %d rids verified OK, fewer than the %d %s, so traces are missing"
          % (len(ok), oks, what))
    bad = 1
sys.exit(bad)' "$1" "$2" "${3:-200s k6 counted}"
}

# failure_orders: one orders container killed (SIGKILL) under load on the route orders: the requests that fail
# (those orders held when it died; a new connection refused is retried by the route's connect-failure retry), and
# orders' traces, each rid served once.
failure_orders() {
  local pod restarts at since_time envoy_before envoy_after p_before p_after users
  pod=$(live_pods app=orders | head -n1)
  users=$(held_pool "$FAILURE_ORDERS_RATE_USED" "$FAILURE_ORDERS_POOL_SECONDS")
  echo "-- one orders container killed (SIGKILL): the route orders offered $FAILURE_ORDERS_RATE_USED/s for" \
    "$FAILURE_ORDERS_DURATION (k6 users: $users), the kill $FAILURE_LEAD s into it; the" \
    "route retries a connection that failed, and nothing that reached orders"
  restarts=$(pod_restarts "$pod")
  envoy_before=$(envoy_orders_retries) && p_before=$(outcomes_by_pod) || return 1
  # From a second before the run, by the node's clock, which the logs' times are on.
  since_time=$(docker exec "$(node_container)" date -u -d '-1 second' +%Y-%m-%dT%H:%M:%S) || return 1
  case_begin failure-orders TARGET="$EDGE/orders" BODY=small EXECUTOR=rate RATE="$FAILURE_ORDERS_RATE_USED" \
    PREALLOC="$users" DURATION="$FAILURE_ORDERS_DURATION" || return 1
  at=$(kill_container "$pod") || return 1
  event_at "$at" "SIGKILL to orders' container in $pod"
  until_ready app=orders 2 "$pod" "$restarts" 300 "both orders replicas ready" || {
    echo "error: orders did not have two replicas ready within 300 s of the kill" >&2
    return 1
  }
  case_end || return 1
  echo "  both orders replicas ready again $(since "$at" "$(event_ms "both orders")") s after the kill (polled" \
    "about every half second, so to within about a second)"
  envoy_after=$(envoy_orders_retries) && p_after=$(outcomes_by_pod) || return 1
  echo "  Envoy counted, of its requests to orders: $(outcomes_added "$envoy_before" "$envoy_after")"
  echo "  the processor decided:"
  outcomes_by_pod_added "$p_before" "$p_after"
  orders_rids "$since_time" "$RUN_DIR/failure-orders"
}

# orders_rids <since> <run>: orders' traces since the time, into <run>.traces, held to the 200s in <run>.result
# (rids_once's lines); a FAIL when either cannot be read.
orders_rids() {
  local traces="$2.traces" oks
  oks=$(sed -n 's/.*"200":\([0-9]*\).*/\1/p' "$2.result" 2>/dev/null)
  if ! orders_traces "$1" >"$traces"; then
    echo "  FAIL orders served each rid once: orders' log files could not be read (above), so nothing can be said"
    FAILURE_FAILS=$((FAILURE_FAILS + 1))
  elif [ -z "$oks" ]; then
    echo "  FAIL orders traces cover the run: k6's count of 200s could not be read, so the traces cannot be held to it"
    FAILURE_FAILS=$((FAILURE_FAILS + 1))
  else
    rids_once "$traces" "$oks" || FAILURE_FAILS=$((FAILURE_FAILS + 1))
  fi
}

# failure_undo: every fault put back: the case's run stopped, a helm upgrade it started let finish, no delay on any
# processor pod, the chart's objects as the chart has them (its policy failing closed; a field changed with kubectl,
# which then owns it, is taken back: helm applies server-side, and would otherwise refuse every later upgrade for
# the conflict), two processor replicas ready, Envoy routing to endpoints, and every orders replica ready. Returns 1
# when any of it could not be done, saying which; a release a helm upgrade left pending (one stopped half-way, by an
# interrupt) is a FAIL, and nothing here rolls it back.
failure_undo() {
  local ok=0 log="$tmp/failure-undo-helm.log" release
  [ -z "$CASE_PID" ] || { kill "$CASE_PID" 2>/dev/null; forget "$CASE_PID"; }
  CASE_PID=""
  [ -z "$HELM_PID" ] || wait "$HELM_PID" 2>/dev/null
  HELM_PID=""
  k6_stop
  netem_clear >/dev/null || { echo "error: could not clear the processor pods' delays" >&2; ok=1; }
  release=$(helm_release)
  case "$release" in
    pending-*)
      echo "  FAIL the processor's chart release is $release: a helm upgrade was stopped half-way, and nothing here" \
        "rolls it back; remove the cluster with poc-demos/envoy-gateway/envoy-gateway.sh down"
      return 1
      ;;
  esac
  measure_chart --force-conflicts >"$log" 2>&1 || {
    echo "error: could not put the processor's chart back; helm said:" >&2
    tail -n 5 "$log" >&2
    ok=1
  }
  [ "$(fail_open)" = false ] || { echo "error: the processor's policy has failOpen $(fail_open), not false" >&2; ok=1; }
  processor_replicas 2 >/dev/null || { echo "error: could not put the processor back to two ready replicas" >&2; ok=1; }
  if [ "$(envoy_routing)" != Endpoint ]; then
    envoy_routing_set Endpoint && wait_measure >/dev/null || {
      echo "error: could not put Envoy back to routing to endpoints" >&2
      ok=1
    }
  fi
  kn rollout status deployment/orders --timeout=300s >/dev/null &&
    kn wait --for=condition=Ready pod -l app=orders --timeout=300s >/dev/null || {
    echo "error: orders' replicas are not all ready" >&2
    ok=1
  }
  return "$ok"
}

# spread <routing>: a steady run on echo at the cases' rate, DURATION long, whether it kept that rate, and how the
# processor's two replicas shared it: each pod's stamped requests, and its share.
spread() {
  local before after line
  before=$(outcomes_by_pod) || return 1
  # shellcheck disable=SC2046 # the settings split on space
  line=$(k6_run "failure-spread-$(lower "$1")" $(echo_run "$DURATION")) || return 1
  after=$(outcomes_by_pod) || return 1
  echo "  Envoy routing to the processor's $(lower "$1")s, $FAILURE_RATE_USED/s for $DURATION: $line"
  # A share is of a steady load: a FAIL is counted against the suite with its other pace checks (pace_line).
  run_rated "failure-spread-$(lower "$1")" || true
  python3 -c 'import sys
def read(text):
    out = {}
    for line in text.splitlines():
        pod, restarts, *rest = line.split()
        out[pod] = (restarts, dict(w.split("=") for w in rest) if rest != ["unread"] else None)
    return out
before, after = read(sys.argv[1]), read(sys.argv[2])
got = {}
for pod, (restarts, counts) in after.items():
    was = before.get(pod)
    if counts is None or not was or was[0] != restarts or was[1] is None:
        print("    %s: its counts could not be compared (new, started again, or unread)" % pod)
        continue
    got[pod] = int(counts["stamped"]) - int(was[1]["stamped"])
total = sum(got.values())
for pod, n in sorted(got.items()):
    print("    %s stamped %d, %.1f%%" % (pod, n, 100.0 * n / total if total else 0))' "$before" "$after"
}

# failure_service: the all-down case again, with Envoy routing to the processor's Service (the EnvoyProxy's
# routingType Service: one host, its cluster IP, which kube-proxy balances per connection) instead of its pods, the
# default; first, how the load spreads over the two replicas under each routing. Then back to endpoints.
failure_service() {
  local code
  echo "-- Envoy routing to Services (the EnvoyProxy edge's routingType Service) against routing to endpoints," \
    "Envoy Gateway's default"
  envoy_admin || return 1
  echo "  Envoy's cluster for the processor holds $(processor_hosts), the processor's pods"
  spread Endpoint || return 1
  envoy_routing_set Service || return 1
  envoy_admin || return 1
  echo "  routing set to Service: Envoy's cluster for the processor holds $(processor_hosts), the cluster IP of the" \
    "Service paztport-processor ($(kn get service paztport-processor -o jsonpath='{.spec.clusterIP}'))"
  wait_measure >/dev/null || {
    echo "error: with Envoy routing to Services, echo or echo-plain does not answer 200 (above)" >&2
    return 1
  }
  code=$(edge_posts 1 /orders)
  echo "  with Envoy routing to Services: echo and echo-plain answer 200, the route orders answers $code"
  [ "$code" = 200 ] || { echo "error: with Envoy routing to Services, the route orders answers $code" >&2; return 1; }
  spread Service || return 1
  echo ""
  failure_down failure-down-service Service || return 1
  envoy_routing_set Endpoint && wait_measure >/dev/null || return 1
  envoy_admin || return 1
  echo "  routing back to endpoints: Envoy's cluster for the processor holds $(processor_hosts)"
}

suite_failure() {
  local status=0 step first=1
  echo "== failure: the edge under load while the processor fails, and while orders does"
  baseline_reset
  FAILURE_FAILS=0
  # The forward to Envoy's admin port, in this shell: one made in a reading's subshell would be lost with it.
  failure_rate && orders_rate FAILURE_ORDERS_RATE "$FAILURE_ORDERS_RATE" &&
    FAILURE_ORDERS_RATE_USED="$ORDERS_RATE_USED" && echo_primed && envoy_admin || return 1
  echo "  Envoy fails closed: a request whose stream to the processor fails is refused with Envoy's own 500, or 504" \
    "when the processor did not answer within messageTimeout (message_timeouts, an ext_proc filter stat); of" \
    "those 500s, the ones its circuit breaker on the processor's cluster refused (past 1024 at a time) are" \
    "cluster_rq_active_overflow, the harness's label for Envoy's upstream_rq_active_overflow. A" \
    "route Envoy Gateway has turned into a direct response is refused before the filter, which counts none of it"
  UNDO="failure_undo"
  for step in failure_kill failure_slow failure_down_endpoint failure_service failure_roll failure_orders; do
    # Each case starts from the baseline: anything the last one left is put back first.
    if [ -z "$first" ] && ! failure_undo; then
      echo "error: what the last case changed could not all be put back; skipping the rest" >&2
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
  echo "-- after the cases"
  echo_unstamped || status=1
  [ "$FAILURE_FAILS" -eq 0 ] || status=1
  return "$status"
}
