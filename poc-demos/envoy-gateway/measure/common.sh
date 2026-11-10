# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# What the measurement suites share: the k6 runs, their alternation and summaries, error windows, the processor's
# pods and the kind node and the faults put on them, echo's and the backends' counts, and the reset to the baseline
# every suite starts from. measure.sh sources it after lib.sh, and sets RUN_DIR (this run's results), tmp (a scratch
# directory) and forwards (the background processes to kill on exit: port-forwards and the like).
# shellcheck shell=bash

# k6, pinned by the digest of its index (k6 2.3.0, released 2026-09-21).
K6_IMAGE=docker.io/grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8
# The twin routes' hosts (kind/measure.yaml): the processor is attached to the first, never to the second.
ECHO_HOST=echo.example
PLAIN_HOST=echo-plain.example
# The HTTPRoutes of the baseline; baseline_reset deletes any other.
BASE_ROUTES="orders orders-unmapped echo echo-plain"
# The BackendTrafficPolicies of the baseline (kind/routes.yaml's and kind/measure.yaml's); baseline_reset deletes any
# other.
BASE_POLICIES="orders-routes echo-routes"
# The BackendTLSPolicies of the baseline (kind/backends.yaml's, for orders, and the chart's, for the processor);
# baseline_reset deletes any other.
BASE_TLS_POLICIES="orders paztport-processor"
# The ConfigMaps and Secrets a suite makes to carry material of its own into the pods (measure/change.sh's): none is
# in the baseline, and baseline_reset deletes them once no pod mounts them.
SUITE_MATERIAL="configmap/measure-policy secret/measure-edge-key"

# measure_chart [helm args...]: the chart as the measurements run it: orders and echo mapped to the receiver
# orders, the autoscaler off and two replicas, unless the args set others.
measure_chart() {
  install_chart --set 'routes[1].httpRoute=echo' --set 'routes[1].receiver=orders' \
    --set autoscaling.enabled=false --set replicas=2 "$@"
}

# helm_release: the processor's chart release's status, such as deployed, failed or pending-upgrade.
helm_release() {
  helm --kube-context "$CTX" -n "$NS" status paztport -o json 2>/dev/null |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["info"]["status"])' 2>/dev/null
}

load_echo_image() {
  kind load docker-image --name "$CLUSTER" paztport-echo:dev
}

# install_measure: what the measurements add to the cluster up made: echo in the chart's routes first, then echo,
# its twin routes and their BackendTrafficPolicy, echo started again, and k6's script.
install_measure() {
  quietly "loading the echo image into kind" load_echo_image
  quietly "mapping echo in the chart" measure_chart --wait --timeout 5m
  quietly "applying echo and the twin routes" apply_routes kind/measure.yaml
  quietly "starting echo again, so that its counts are this run's" echo_restart
  quietly "loading k6's script" apply_files "$NS" configmap k6-edge "edge.js=$here/measure/k6/edge.js"
  quietly "waiting for the twin routes" wait_measure
}

# echo_restart: echo's pods started again, and its old ones gone, for up to 60 s. echo's counts are its process's,
# from its start, and a cluster an earlier run kept (measure.sh --reuse) holds that run's: started again, they are
# this run's alone, and every line on them is this run's.
echo_restart() {
  local all live
  kn rollout restart deployment/echo && kn rollout status deployment/echo --timeout=120s || return 1
  for _ in $(seq 1 120); do
    all=$(kn get pods -l app=echo -o name | grep -c . || true)
    live=$(echo_pod_uids | wc -w | tr -d ' ')
    [ "$all" -eq "$live" ] && return 0
    sleep 0.5
  done
  echo "error: echo's old pods were still there 60 s after it was started again: $all pods, $live new" >&2
  return 1
}

# edge_posts <n> <path> [host]: n POSTs of an empty JSON body to the path through the Gateway, with the Host header
# given (none by default), from the pod checks, one after another in one kubectl exec; prints each one's status, one
# a line.
edge_posts() {
  # shellcheck disable=SC2016 # the script runs in the pod's shell
  kn exec checks -- sh -c 'i=0; while [ "$i" -lt "$1" ]; do
    if [ -n "$4" ]; then
      curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "host: $4" -H "content-type: application/json" -d "{}" "$2$3"
    else
      curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "content-type: application/json" -d "{}" "$2$3"
    fi
    i=$((i + 1)); done' sh "$1" "$EDGE" "$2" "${3:-}" 2>/dev/null
}

# edge_status <host>: the status of one POST /orders through the Gateway for the host, from the pod checks. A 200
# on a twin's host is a request echo answered, and goes into the tally echo's counts are checked against.
edge_status() {
  local code
  code=$(edge_posts 1 /orders "$1")
  [ "$code" != 200 ] || echo_tally "$1" 1
  printf '%s' "$code"
}

# The tally of the requests echo answered 200 through the Gateway, by host, since echo's present pods started: one
# "<host> <n>" a line in $RUN_DIR/echo-sent, made new whenever echo's pods are not those recorded in
# $RUN_DIR/echo-pods (their uids), since a new pod's counts start from nothing.

# echo_pod_uids: the uids of echo's running pods that are not being deleted, sorted, on one line.
echo_pod_uids() {
  kn get pods -l app=echo --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.uid} {.metadata.deletionTimestamp}{"\n"}{end}' |
    awk 'NF == 1 { print $1 }' | LC_ALL=C sort | paste -sd " " -
}

# echo_tally_begin: starts the tally again when echo's pods are not the ones it was kept for.
echo_tally_begin() {
  local uids
  uids=$(echo_pod_uids)
  if [ "$uids" != "$(cat "$RUN_DIR/echo-pods" 2>/dev/null)" ]; then
    printf '%s\n' "$uids" >"$RUN_DIR/echo-pods"
    : >"$RUN_DIR/echo-sent"
  fi
}

# echo_tally <host> <n>: adds n requests answered 200 on a twin's host to the tally.
echo_tally() {
  case "$1" in "$ECHO_HOST" | "$PLAIN_HOST") echo "$1 $2" >>"$RUN_DIR/echo-sent" ;; esac
}

# wait_measure: wait_edge, then until echo is ready, the twins' BackendTrafficPolicy is accepted, and Envoy answers
# 200 on both twins, for up to 60 s.
wait_measure() {
  local host code
  wait_edge &&
    policy_attached backendtrafficpolicy/echo-routes &&
    kn rollout status deployment/echo --timeout=120s || return 1
  echo_tally_begin
  for host in "$ECHO_HOST" "$PLAIN_HOST"; do
    for _ in $(seq 1 60); do
      code=$(edge_status "$host")
      [ "$code" = 200 ] && break
      sleep 1
    done
    [ "$code" = 200 ] || { echo "the route for $host answers $code, not 200" >&2; return 1; }
  done
}

# run_seconds <duration> <stages>: how long a k6 run lasts, in whole seconds: its DURATION (k6's form, such as
# 20s, 1m30s or 500ms), or the sum of its STAGES' durations.
run_seconds() {
  python3 -c 'import json, math, re, sys
def secs(d):
    parts = re.findall(r"([0-9.]+)(ms|h|m|s)", d)
    if not parts or "".join(n + u for n, u in parts) != d:
        sys.exit("not a k6 duration: %r" % d)
    return sum(float(n) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[u] for n, u in parts)
total = secs(sys.argv[1]) if sys.argv[1] else sum(secs(st["duration"]) for st in json.loads(sys.argv[2] or "[]"))
print(math.ceil(total))' "$1" "$2"
}

# The memory k6's pod may use: enough for the pools the suites give it (about a third of a megabyte a user, and the
# per-second counts). A run that needs more sets it for itself (K6_MEMORY=4Gi k6_run ...).
K6_MEMORY=2Gi

# How long k6_run waits beyond a run's own length: edge.js's gracefulStop (15 s), and the pod's scheduling, image
# pull and start.
K6_MARGIN=120

# How long a finished k6 Job is kept, in seconds, should k6_run not delete it (an interrupt while it waits).
K6_JOB_TTL=300

# k6_stop: every k6 Job deleted, and its pod with it: a run's own, or one an interrupted run left.
k6_stop() {
  kn delete job -l app=k6 --ignore-not-found >/dev/null 2>&1
}

# k6_running <name>: waits until the pod of the k6 run in the background is running, for up to 300 s; returns 1,
# saying so, when it is not.
k6_running() {
  local phase=""
  for _ in $(seq 1 300); do
    phase=$(kn get pods -l "job-name=k6-$1" -o jsonpath='{.items[*].status.phase}' 2>/dev/null)
    [ "$phase" = Running ] && return 0
    sleep 1
  done
  echo "error: the k6 run $1 did not start (its pod: ${phase:-none})" >&2
  return 1
}

# run_wait <pid> <name>: waits for a k6 run in the background (k6_run, its output in $tmp/<name>.line and its
# errors in $tmp/<name>.err), takes it out of forwards, and prints its errors and then the run; whether it kept its
# rate (run_rated: such a run is a case under a fault or a change, at a constant rate); and, when k6 dropped
# requests, that its counts are a lower bound. Returns 1 when the run failed.
run_wait() {
  local status dropped
  wait "$1"
  status=$?
  forget "$1"
  [ ! -s "$tmp/$2.err" ] || sed 's/^/  /' "$tmp/$2.err"
  [ "$status" -eq 0 ] || return 1
  printf '  %s: %s\n' "$2" "$(cat "$tmp/$2.line")"
  # A FAIL is counted against the suite with its other pace checks (pace_line).
  run_rated "$2" || true
  dropped=$(sed -n 's/.*"dropped":\([0-9]*\).*/\1/p' "$tmp/$2.line")
  if [ "${dropped:-0}" -gt 0 ]; then
    echo "  k6 had no free user for $dropped of the requests it was to send, so they were never sent: every count" \
      "of $2, the errors' included, is a lower bound set by k6's pool"
  fi
}

# k6_run <name> <VAR=value>...: runs measure/k6/edge.js in the Job k6-<name>, with the settings given (the last of
# a name wins), and waits for it, for the run's length and K6_MARGIN more; prints its RESULT line, writes its FAIL
# lines to $RUN_DIR/<name>.fails, the expected status and the RESULT line to $RUN_DIR/<name>.result, and its WINDOW
# line to $RUN_DIR/<name>.window (for window and timeline), holds the run to its time (run_timed), adds the 200s on
# a twin's host to echo's tally, and deletes the Job. Returns 1, with what it saw, when the run timed out (or its
# pod never started) or printed no RESULT line. Warns, without failing, when the Job failed though k6 printed a
# RESULT line, and when the RESULT's statuses, or the WINDOW's seconds, do not sum to its requests.
k6_run() {
  local name="$1" job="k6-$1" kv later seen env="" log state i j expect=200 result duration="" stages="" host="" rate=""
  local length wait phase
  shift
  local vars=("$@")
  for ((i = 0; i < ${#vars[@]}; i++)); do
    kv="${vars[$i]}"
    seen=""
    for ((j = i + 1; j < ${#vars[@]}; j++)); do
      later="${vars[$j]}"
      [ "${later%%=*}" != "${kv%%=*}" ] || seen=1
    done
    [ -z "$seen" ] || continue
    case "${kv%%=*}" in
      EXPECT) expect="${kv#*=}" ;;
      DURATION) duration="${kv#*=}" ;;
      RATE) rate="${kv#*=}" ;;
      STAGES) stages="${kv#*=}" ;;
      HOST) host="${kv#*=}" ;;
    esac
    # Each value as a YAML single-quoted string, which holds anything but a single quote, written twice.
    env+="            - {name: ${kv%%=*}, value: '$(printf '%s' "${kv#*=}" | sed "s/'/''/g")'}"$'\n'
  done
  kn delete job "$job" --ignore-not-found >/dev/null 2>&1
  kn apply -f - >/dev/null <<EOF || return 1
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  namespace: $NS
  labels: {app: k6}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: $K6_JOB_TTL
  template:
    metadata:
      labels: {app: k6}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 12345
        runAsGroup: 12345
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: k6
          image: $K6_IMAGE
          args: [run, --quiet, --no-color, --log-format=raw, /scripts/edge.js]
          env:
$env          resources:
            requests: {cpu: "2", memory: 512Mi}
            limits: {cpu: "2", memory: $K6_MEMORY}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: scripts, mountPath: /scripts, readOnly: true}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: scripts
          configMap: {name: k6-edge}
        - name: tmp
          emptyDir: {}
EOF
  length=$(run_seconds "$duration" "$stages") || return 1
  wait=$((length + K6_MARGIN))
  state=""
  for _ in $(seq 1 "$wait"); do
    state=$(kn get job "$job" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null)
    case "$state" in 1/* | */1) break ;; esac
    sleep 1
  done
  case "$state" in
    1/* | */1) ;;
    *)
      phase=$(kn get pods -l "job-name=$job" \
        -o jsonpath='{range .items[*]}{.status.phase} {.status.conditions[?(@.type=="PodScheduled")].reason}{end}')
      case "$phase" in
        "" | Pending*)
          echo "error: the k6 run $name timed out after $wait s: its pod never started (${phase:-no pod})" >&2 ;;
        *)
          echo "error: the k6 run $name timed out after $wait s, its pod ${phase% }; its last output:" >&2
          kn logs "job/$job" 2>&1 | tail -n 20 >&2 ;;
      esac
      kn delete job "$job" --wait=false >/dev/null 2>&1
      return 1
      ;;
  esac
  log="$tmp/$job.log"
  kn logs "job/$job" >"$log" 2>&1
  kn delete job "$job" --wait=false >/dev/null 2>&1
  grep '^FAIL ' "$log" >"$RUN_DIR/$name.fails"
  result=$(grep -m1 '^RESULT ' "$log") || {
    echo "error: the k6 run $name (job state $state) printed no RESULT line. Its last output:" >&2
    tail -n 20 "$log" >&2
    return 1
  }
  case "$state" in
    */1) echo "warning: the k6 run $name printed a RESULT line, but its Job failed (k6 exited non-zero):" \
      "$(grep -v '^FAIL \|^RESULT \|^WINDOW ' "$log" | tail -n 3 | tr '\n' ' ')" >&2 ;;
  esac
  grep -m1 '^WINDOW ' "$log" >"$RUN_DIR/$name.window"
  python3 -c 'import json, sys
r = json.loads(sys.argv[2][len("RESULT "):])
total = sum(r["status"].values())
if total != r["reqs"]:
    print("warning: the k6 run %s: its statuses sum to %d, not to its %d requests" % (sys.argv[1], total, r["reqs"]))
if not sys.argv[3]:
    print("warning: the k6 run %s printed no WINDOW line" % sys.argv[1])
else:
    w = json.loads(sys.argv[3][len("WINDOW "):])
    seconds = sum(sum(w[k]) for k in ("expected", "5xx", "rest")) + w["late"]
    if seconds != r["reqs"]:
        print("warning: the k6 run %s: its WINDOW counts %d responses, not its %d requests" % (sys.argv[1], seconds,
              r["reqs"]))' "$name" "$result" "$(cat "$RUN_DIR/$name.window")" >&2
  printf '%s %s\n' "$expect" "$result" >"$RUN_DIR/$name.result"
  # An open-model run's plan, its rate and length in seconds, for run_rated.
  if [ -n "$rate" ] && [ -n "$duration" ]; then
    printf '%s %s\n' "$rate" "$length" >"$RUN_DIR/$name.plan"
  fi
  # A FAIL goes to stderr, beside the run's own errors: the RESULT line alone is the run's output.
  [ -z "$duration$stages" ] || run_timed "$name" "$length" >&2
  [ -z "$host" ] || echo_tally "$host" "$(printf '%s' "$result" | sed -n 's/.*"200":\([0-9]*\).*/\1/p')"
  printf '%s\n' "$result"
}

# The seconds past a run's length and edge.js's gracefulStop (15 s) that its summary may come before run_timed takes
# it for a run the host held up.
PACE_SLACK=10

# The pace checks of this run's k6 runs, one a line, in $RUN_DIR/pace: "<name> time PASS|FAIL <seconds past its
# length>" for every run of known length (run_timed), and "<name> rate PASS|FAIL" for every run that must keep its
# offered rate (run_rated). measure.sh holds each suite to the checks its runs added (pace_line).

# run_timed <name> <length>: the check that a k6 run kept to its time: its summary came no later than its length,
# the gracefulStop and PACE_SLACK seconds after it began, by k6's clock. A host that stalled or slept (a laptop's
# idle sleep, say) holds k6 up with the rest, and the run's numbers are then not of the load it was given, whatever
# its own rate says, as k6 sends nothing while it is held. Prints a FAIL line, and returns 1, for a run held up, or
# one whose WINDOW line gives no time; prints nothing for a run that kept to it. Every run of known length takes it.
run_timed() {
  python3 -c 'import json, sys
run, secs, slack = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
name = run.rsplit("/", 1)[1]
try:
    w = json.loads(open(run + ".window").read()[len("WINDOW "):])
except (OSError, ValueError):
    w = {}
wall = (w["end"] - w["t0"]) / 1000 if w.get("end") and w.get("t0") else None
past = None if wall is None else wall - secs
held = wall is None or past - 15 > slack
with open(run.rsplit("/", 1)[0] + "/pace", "a") as f:
    f.write("%s time %s %s\n" % (name, "FAIL" if held else "PASS", "-" if past is None else "%.1f" % past))
if held:
    print("  FAIL %s kept to its time: its summary came %s, for a run of %gs: more than the gracefulStop (15 s)"
          " and %g s past its length, so the host stalled or slept, and this run'"'"'s numbers are not of the load it"
          " was given" % (name, "at no known time" if wall is None else "%.1f s after it began" % wall, secs,
                          slack))
    sys.exit(1)' "$RUN_DIR/$1" "$2" "$PACE_SLACK"
}

# run_rated <name>: the behavioural line that an open-model run (one k6_run gave a RATE and a DURATION) kept to its
# offered rate: k6 achieved it within 2%, with no request dropped (the rule summary.py's rate check applies to the
# warm-ups). Only a run that must keep its rate takes it: an alternated round, a steady run, a case under a fault or
# a change; a ceiling, saturation, ramp or overload stage measures what is achieved, and does not. Returns 1 on FAIL;
# prints nothing for a run without a plan.
run_rated() {
  [ -f "$RUN_DIR/$1.plan" ] || return 0
  python3 -c 'import json, sys
run = sys.argv[1]
rate = float(open(run + ".plan").read().split()[0])
r = json.loads(open(run + ".result").read().strip().partition(" ")[2][len("RESULT "):])
name = run.rsplit("/", 1)[1]
off = (r["rps"] - rate) / rate * 100
kept = abs(off) <= 2 and r["dropped"] == 0
with open(run.rsplit("/", 1)[0] + "/pace", "a") as f:
    f.write("%s rate %s\n" % (name, "PASS" if kept else "FAIL"))
said = "%.1f/s achieved of %g/s offered (%+.1f%%), %d dropped" % (r["rps"], rate, off, r["dropped"])
if kept:
    print("  PASS %s kept its rate: %s" % (name, said))
    sys.exit(0)
print("  FAIL %s kept its rate: %s: k6 did not keep to it (the host stalled, or k6 ran short of users), so this"
      " run'"'"'s numbers are not of a steady load at that rate" % (name, said))
sys.exit(1)' "$RUN_DIR/$1"
}

# pace_mark: how many pace checks this run has recorded so far, for pace_line.
pace_mark() {
  if [ -f "$RUN_DIR/pace" ]; then grep -c . "$RUN_DIR/pace" || true; else echo 0; fi
}

# pace_line <mark>: the behavioural line on a suite's k6 runs, from the pace checks recorded after mark (pace_mark,
# before the suite): every run of known length kept to its time, and every run that must keep its rate kept it.
# Returns 1 on FAIL; says so, with no line, for a suite that ran no k6 run.
pace_line() {
  python3 -c 'import sys
checks = []
try:
    with open(sys.argv[1]) as f:
        checks = [line.split() for line in f if line.strip()][int(sys.argv[2]):]
except OSError:
    pass
timed = [c for c in checks if c[1] == "time"]
rated = [c for c in checks if c[1] == "rate"]
if not checks:
    print("  no k6 run in the suite, so no line on their pace")
    sys.exit(0)
late = [c[0] for c in timed if c[2] != "PASS"]
missed = [c[0] for c in rated if c[2] != "PASS"]
past = [float(c[3]) for c in timed if c[3] != "-"]
if not late and not missed and timed:
    print("  PASS the suite'"'"'s k6 runs kept their pace: each of its %d runs kept to its time (the latest summary"
          " %.1f s after its run'"'"'s length), and %s" % (
              len(timed), max(past), "each of the %d that must keep its rate kept it" % len(rated) if rated
              else "none of them must keep a rate (each measures what it achieves)"))
    sys.exit(0)
why = []
if not timed:
    why.append("no run of known length was held to its time")
if late:
    why.append("%d of %d ran past their time (%s)" % (len(late), len(timed), ", ".join(late[:5])))
if missed:
    why.append("%d of %d missed their rate (%s)" % (len(missed), len(rated), ", ".join(missed[:5])))
print("  FAIL the suite'"'"'s k6 runs kept their pace: %s, so their numbers are not of the load they were given"
      % "; ".join(why))
sys.exit(1)' "$RUN_DIR/pace" "$1"
}

# alternate <name> <labelA> <setupA> <labelB> <setupB> <VAR=value>...: compares two setups like for like. Each
# setup is a command, evaluated before each run of its label, that may set RUN_VARS (an array) to that label's own
# k6 settings. First a warm-up of each label (WARMUP long, discarded; none when WARMUP is 0, for setups that warm
# up themselves); then ROUNDS rounds of one run of each (DURATION long), the leading label alternating from round to
# round. Prints each run, and whether it kept its rate (run_rated: a comparison is of two sides at the same load), then
# summary.py's medians, spread and what B adds to A.
alternate() {
  local name="$1" la="$2" sa="$3" lb="$4" sb="$5" round label setup line order
  shift 5
  local runs="$RUN_DIR/$name.runs"
  : >"$runs"
  for label in "$la" "$lb"; do
    # WARMUP=0: the setups warm up themselves.
    [ "$WARMUP" != 0 ] || break
    if [ "$label" = "$la" ]; then setup="$sa"; else setup="$sb"; fi
    RUN_VARS=()
    eval "$setup" || return 1
    line=$(k6_run "$name-$label-warmup" "$@" ${RUN_VARS[@]+"${RUN_VARS[@]}"} DURATION="$WARMUP") || return 1
    printf '  warm-up  %-8s %s (discarded)\n' "$label" "$line"
  done
  for round in $(seq 1 "$ROUNDS"); do
    if [ $((round % 2)) -eq 1 ]; then order="$la $lb"; else order="$lb $la"; fi
    for label in $order; do
      if [ "$label" = "$la" ]; then setup="$sa"; else setup="$sb"; fi
      RUN_VARS=()
      eval "$setup" || return 1
      line=$(k6_run "$name-$label-r$round" "$@" ${RUN_VARS[@]+"${RUN_VARS[@]}"}) || return 1
      printf '  round %-2s %-8s %s\n' "$round" "$label" "$line"
      # A FAIL is counted against the suite with its other pace checks (pace_line).
      run_rated "$name-$label-r$round" || true
      printf '%s %s\n' "$label" "$line" >>"$runs"
    done
  done
  python3 "$here/measure/summary.py" medians "$runs" "$la" "$lb"
}

# window <fails file>: the responses other than the expected that a run saw: how many, by status, the first and
# the last, and the span between them, from the run's WINDOW line, which counts every response. (For a run without
# one, from the FAIL lines k6 listed, saying so when it listed fewer than the run counted: it lists at most 20000.)
window() {
  python3 "$here/measure/summary.py" window "$1"
}

# live_pods <selector>: the pods the selector picks that are running and not being deleted, one a line.
live_pods() {
  kn get pods -l "$1" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp}{"\n"}{end}' |
    awk 'NF == 1 { print $1 }'
}

processor_pods() {
  live_pods app.kubernetes.io/name=paztport-processor
}

# node_container: the kind node's Docker container, the cluster's one node.
node_container() {
  echo "$CLUSTER-control-plane"
}

# pod_pid <pod>: the pid of the pod's sandbox on the node, whose network namespace is the pod's.
pod_pid() {
  local sandbox
  sandbox=$(docker exec "$(node_container)" crictl pods --namespace "$NS" --name "^$1\$" -q 2>/dev/null | head -n1)
  [ -n "$sandbox" ] || return 1
  docker exec "$(node_container)" crictl inspectp -o go-template --template '{{.info.pid}}' "$sandbox" 2>/dev/null
}

# pod_tc <pod> <tc args...>: runs tc in the pod's network namespace, from the kind node.
pod_tc() {
  local pod="$1" pid
  shift
  pid=$(pod_pid "$pod") && [ -n "$pid" ] || { echo "no sandbox for the pod $pod" >&2; return 1; }
  docker exec "$(node_container)" nsenter -t "$pid" -n tc "$@"
}

# netem_clear: removes a netem queue, and the prio queue slow_pod puts one under, from each processor pod's
# interface, and prints from how many pods it removed one.
netem_clear() {
  local pod n=0 qdiscs
  for pod in $(processor_pods); do
    qdiscs=$(pod_tc "$pod" qdisc show dev eth0) || return 1
    if grep -qE '^qdisc (netem|prio) ' <<<"$qdiscs"; then
      pod_tc "$pod" qdisc del dev eth0 root || return 1
      n=$((n + 1))
    fi
  done
  echo "$n"
}

# node_ms: the kind node's time, in epoch ms: the clock k6 reads, as every pod on the node does.
node_ms() {
  docker exec "$(node_container)" date +%s%3N
}

# The case running now, in a suite whose cases each run k6 under a fault or a change: its name, which its files in
# $RUN_DIR are named after.
CASE=""

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

# event_ms <what>: the time of the case's first event that begins with what, or empty.
event_ms() {
  awk -v w="$1" 'index(substr($0, index($0, " ") + 1), w) == 1 { print $1; exit }' "$RUN_DIR/$CASE.events"
}

# since <from ms> <to ms>: the seconds between the two times, as "12.34".
since() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", (b - a) / 1000 }'
}

# pod_netns <pod> <script>: runs the sh script, which stops at its first failing command, in the pod's network
# namespace, from the kind node (and with the node's tc); then prints the node's time, in epoch ms.
pod_netns() {
  local pod="$1" pid
  pid=$(pod_pid "$pod") && [ -n "$pid" ] || { echo "no sandbox for the pod $pod" >&2; return 1; }
  docker exec "$(node_container)" nsenter -t "$pid" -n sh -ec "$2
date +%s%3N"
}

# slow_pod <pod> <ms> grpc|all: delays the packets the pod sends by ms, with tc netem in its network namespace:
# grpc, only those from port 9002, the processor's gRPC port, so that it answers Envoy late while its probes, on
# 9090, still answer in time; all, every packet, its probes' answers too. A delay already there is replaced. Prints
# the node's time once the delay is in place, in epoch ms.
slow_pod() {
  local script="tc qdisc del dev eth0 root 2>/dev/null || true"
  case "$3" in
    # A prio queue whose priomap sends every packet to its first band, and a filter that sends those from port 9002
    # to its third, the one under netem.
    grpc) script+="
tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev eth0 parent 1:3 handle 30: netem delay $2ms
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip sport 9002 0xffff flowid 1:3" ;;
    all) script+="
tc qdisc add dev eth0 root netem delay $2ms" ;;
    *)
      echo "slow_pod: grpc or all, not $3" >&2
      return 1
      ;;
  esac
  pod_netns "$1" "$script"
}

# unslow_pod <pod>: removes what slow_pod added to the pod's interface, and checks that no netem or prio queue is
# left; prints the node's time once it is gone, in epoch ms.
unslow_pod() {
  pod_netns "$1" "tc qdisc del dev eth0 root 2>/dev/null || true
if tc qdisc show dev eth0 | grep -qE '^qdisc (netem|prio) '; then exit 1; fi"
}

# kill_container <pod>: SIGKILLs the pod's running container's process, from the kind node, as the kernel's OOM
# killer would; the kubelet then starts the container again. Prints the node's time of the kill, in epoch ms.
kill_container() {
  local node sandbox cid pid
  node=$(node_container)
  sandbox=$(docker exec "$node" crictl pods --namespace "$NS" --name "^$1\$" -q 2>/dev/null | head -n1)
  [ -n "$sandbox" ] || { echo "no sandbox for the pod $1" >&2; return 1; }
  cid=$(docker exec "$node" crictl ps --pod "$sandbox" --state running -q 2>/dev/null | head -n1)
  [ -n "$cid" ] || { echo "no running container in the pod $1" >&2; return 1; }
  pid=$(docker exec "$node" crictl inspect -o go-template --template '{{.info.pid}}' "$cid" 2>/dev/null)
  case "$pid" in
    "" | *[!0-9]* | 0 | 1) echo "no process for the container in the pod $1 (${pid:-none})" >&2; return 1 ;;
  esac
  # shellcheck disable=SC2016 # the script runs in the node's shell
  docker exec "$node" sh -c 'kill -KILL "$1" && date +%s%3N' sh "$pid"
}

# fail_open: the processor's EnvoyExtensionPolicy's failOpen, as the cluster has it (the chart sets false).
fail_open() {
  kn get envoyextensionpolicy paztport-processor -o jsonpath='{.spec.extProc[0].failOpen}'
}

# The files each pod mounts from out/, as "<volume>/<file>=<path in out/>", and the volumes they are in.
ORDERS_FILES="keys/orders.key=keys/orders.key keys/keyring.json=keys/keyring.json keys/policy.pub=keys/policy.pub
  policy/root.json=policy/root.json policy/proofs-orders.json=policy/proofs-orders.json
  tls/orders.crt=keys/tls/orders.crt tls/orders.key=keys/tls/orders.key tls/ca.crt=keys/tls/ca.crt"
PAYMENT_FILES="keys/payment.key=keys/payment.key keys/keyring.json=keys/keyring.json keys/policy.pub=keys/policy.pub
  policy/root.json=policy/root.json tls/payment.crt=keys/tls/payment.crt tls/payment.key=keys/tls/payment.key
  tls/ca.crt=keys/tls/ca.crt"
# routes.txt, in the processor's policy volume, is the chart's own, not material.
PROCESSOR_FILES="key/edge.key=keys/edge.key tls/tls.crt=keys/tls/paztport-processor.crt
  tls/tls.key=keys/tls/paztport-processor.key ca/ca.crt=keys/tls/ca.crt policy/policy.pub=keys/policy.pub
  policy/keyring-0.json=keys/keyring.json policy/root-0.json=policy/root.json
  policy/proofs-edge.json=policy/proofs-edge.json"

# mounted <pod> <volume>...: "<sha256>  <volume>/<file>" for each file in the pod's volumes of those names, as the
# node holds them, but routes.txt.
mounted() {
  local pod="$1" uid
  shift
  uid=$(kn get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
  # shellcheck disable=SC2016 # the script runs in the node's shell
  docker exec "$(node_container)" sh -c 'cd "/var/lib/kubelet/pods/$1/volumes" || exit 1
    shift
    for d in kubernetes.io~*/*; do
      v="${d#*/}"
      case " $* " in *" $v "*) ;; *) continue ;; esac
      for f in "$d"/*; do
        [ -f "$f" ] && [ "${f##*/}" != routes.txt ] && echo "$(sha256sum <"$f" | cut -d" " -f1)  $v/${f##*/}"
      done
    done' sh "$uid" "$@" | LC_ALL=C sort -k2
}

# expected <files>: "<sha256>  <volume>/<file>" for each of the files, from out/.
expected() {
  # shellcheck disable=SC2086 # the list splits on space
  python3 -c 'import hashlib, sys
for pair in sys.argv[2:]:
    name, path = pair.split("=", 1)
    print(hashlib.sha256(open(sys.argv[1] + "/" + path, "rb").read()).hexdigest() + "  " + name)' "$here/out" $1 |
    LC_ALL=C sort -k2
}

# material_matches: whether every file orders, payment and the processor mount from out/ is the one in out/ now,
# and no other file is in those volumes; prints each pod that differs, and how. Returns the number of pods checked
# as MATERIAL_PODS.
material_matches() {
  local app files vols pod want got bad=0
  MATERIAL_PODS=0
  for app in orders payment processor; do
    case "$app" in
      orders) files="$ORDERS_FILES" vols="keys policy tls" ;;
      payment) files="$PAYMENT_FILES" vols="keys policy tls" ;;
      processor) files="$PROCESSOR_FILES" vols="key tls ca policy" ;;
    esac
    want=$(expected "$files") || return 1
    local selector="app=$app"
    [ "$app" != processor ] || selector=app.kubernetes.io/name=paztport-processor
    for pod in $(live_pods "$selector"); do
      # shellcheck disable=SC2086 # the volumes split on space
      got=$(mounted "$pod" $vols) || { echo "error: could not read the files the pod $pod mounts" >&2; return 1; }
      MATERIAL_PODS=$((MATERIAL_PODS + 1))
      if [ "$got" != "$want" ]; then
        bad=$((bad + 1))
        echo "error: the pod $pod mounts material that is not out/'s:" >&2
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") |
          sed -n 's/^</  out\/ has:   /p; s/^>/  pod has:    /p' >&2
      fi
    done
  done
  [ "$bad" -eq 0 ]
}

# baseline_reset: puts the cluster back as every suite starts from it, and prints that state. No processor pod has a
# netem queue (cleared first of all, since a delayed pod may not be ready, and every wait would then time out); no k6
# Job is left (one an interrupted run left would load the node through the next suite's runs); any HTTPRoute but orders,
# orders-unmapped, echo and echo-plain is taken off the Gateway, first, so that no route the chart then stops mapping is
# ever served without the processor, and any BackendTrafficPolicy but theirs and any BackendTLSPolicy but orders' and
# the processor's deleted; then the chart is the measurements' (two replicas, the autoscaler off, out/'s material), the
# routes, echo and its twin routes and the backends are as their files have them (enforce mode, out/'s material, their
# replicas, scaled back if a suite left another count, and no environment variable the file does not set: the run stops
# on one), everything is ready, a suite's own material objects are deleted, and Envoy routes to endpoints, its default
# (a routingType a suite set is removed, and the wait made again). A step that fails stops the whole run, and so does an
# EnvoyExtensionPolicy that fails open, or material in any pod that is not out/'s: a suite that broke must not leave the
# next one measuring something else. Nothing is rolled when nothing changed.
baseline_reset() {
  local route policy name netem modes hpa replicas routes routing object replicas_back
  netem=$(netem_clear) || { echo "error: could not read or clear the processor pods' queues" >&2; exit 1; }
  quietly "deleting any k6 Job left" k6_stop
  for route in $(kn get httproutes -o name); do
    name="${route#*/}"
    case " $BASE_ROUTES " in
      *" $name "*) ;;
      *) quietly "deleting the route $name" kn delete httproute "$name" ;;
    esac
  done
  for policy in $(kn get backendtrafficpolicies -o name); do
    name="${policy#*/}"
    case " $BASE_POLICIES " in
      *" $name "*) ;;
      *) quietly "deleting the BackendTrafficPolicy $name" kn delete backendtrafficpolicy "$name" ;;
    esac
  done
  for policy in $(kn get backendtlspolicies -o name); do
    name="${policy#*/}"
    case " $BASE_TLS_POLICIES " in
      *" $name "*) ;;
      *) quietly "deleting the BackendTLSPolicy $name" kn delete backendtlspolicy "$name" ;;
    esac
  done
  quietly "resetting the chart" measure_chart --wait --timeout 5m
  quietly "resetting the routes" apply_routes kind/routes.yaml
  quietly "resetting echo and the twin routes" apply_routes kind/measure.yaml
  quietly "resetting the backends" k apply -f kind/backends.yaml
  replicas_back=$(backends_replicas_back) || {
    echo "error: orders and payment could not be put back to kind/backends.yaml's replicas; stopping" >&2
    exit 1
  }
  quietly "waiting for the baseline" wait_measure
  for object in $SUITE_MATERIAL; do
    quietly "deleting the $object" kn delete "$object" --ignore-not-found
  done
  routing=$(envoy_routing) || { echo "error: could not read the EnvoyProxy's routingType" >&2; exit 1; }
  if [ "$routing" != Endpoint ]; then
    # Not through quietly: its subshell would lose the forward to Envoy's admin port the wait makes.
    envoy_routing_set Endpoint || { echo "error: could not put Envoy back to routing to endpoints" >&2; exit 1; }
    quietly "waiting for the baseline" wait_measure
    routing="Endpoint (routingType $routing removed)"
  fi
  backends_env_matches || {
    echo "error: the backends do not run as kind/backends.yaml has them; stopping" >&2
    exit 1
  }
  material_matches || { echo "error: the cluster's material is not out/'s; stopping" >&2; exit 1; }
  if [ "$(fail_open)" != false ]; then
    echo "error: the processor's EnvoyExtensionPolicy has failOpen $(fail_open), not the chart's false; stopping" >&2
    exit 1
  fi
  local mode='{.spec.template.spec.containers[0].env[?(@.name=="PAZTPORT_MODE")].value}'
  modes=$(kn get deployment orders payment -o jsonpath="{range .items[*]}{.metadata.name}=$mode {end}")
  hpa=$(kn get hpa -o name | grep -c . || true)
  replicas=$(kn get deployment paztport-processor -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')
  routes=$(kn get httproutes -o jsonpath='{.items[*].metadata.name}')
  routes+="; BackendTrafficPolicies $(kn get backendtrafficpolicies -o jsonpath='{.items[*].metadata.name}')"
  routes+="; BackendTLSPolicies $(kn get backendtlspolicies -o jsonpath='{.items[*].metadata.name}')"
  echo "  baseline: processor $replicas ready, $hpa autoscaler(s), failOpen false; Envoy routing to $routing;" \
    "${modes% }; $replicas_back; routes $routes; netem removed from $netem pod(s), none left; material as out/'s" \
    "in $MATERIAL_PODS pods"
}

# json_items: the objects of kubectl's JSON on stdin, one document or several (as kubectl create -o json writes a
# file of many), a List's items in its place, as one JSON array.
json_items() {
  python3 -c 'import json, sys
text, docs, at = sys.stdin.read(), [], 0
decoder = json.JSONDecoder()
while text[at:].strip():
    while text[at].isspace():
        at += 1
    doc, at = decoder.raw_decode(text, at)
    docs += doc.get("items", [doc]) if doc.get("kind") == "List" else [doc]
json.dump(docs, sys.stdout)'
}

# backends_replicas_back: orders and payment scaled back to the replicas kind/backends.yaml gives them, where a suite
# left them at another count (the gotchas suite scales payment to 0), and their rollouts waited for. Prints each
# one's replicas, and which were scaled back from what.
backends_replicas_back() {
  local want d n got said="" back=""
  want=$(k create --dry-run=client -o json -f kind/backends.yaml | json_items | python3 -c 'import json, sys
for d in json.load(sys.stdin):
    if d.get("kind") == "Deployment" and d["metadata"]["name"] in ("orders", "payment"):
        print(d["metadata"]["name"], d["spec"].get("replicas", 1))') && [ -n "$want" ] || return 1
  while read -r d n; do
    got=$(kn get deployment "$d" -o jsonpath='{.spec.replicas}') || return 1
    if [ "$got" != "$n" ]; then
      kn scale "deployment/$d" --replicas="$n" >/dev/null || return 1
      back+=", $d from $got"
    fi
    kn rollout status "deployment/$d" --timeout=300s >/dev/null || return 1
    said+="${said:+, }$d $n"
  done <<<"$want"
  printf '%s replicas%s' "$said" "${back:+ (scaled back: ${back#, })}"
}

# echo_counts: echo's counts, added up over its running pods: "<host> stamped=<n> unstamped=<n>" a line. Returns 1,
# saying which, when there is no such pod, or one does not answer, or answers with no count at all: a pod that has
# counted nothing under load has lost its counts (it started again), so its silence is not a zero.
echo_counts() {
  local pods pod ip out all=""
  pods=$(kn get pods -l app=echo --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP} {.metadata.deletionTimestamp}{"\n"}{end}' |
    awk 'NF == 2')
  [ -n "$pods" ] || { echo "error: no echo pod is running" >&2; return 1; }
  while read -r pod ip; do
    out=$(kn exec checks -- curl -sf --max-time 10 "http://$ip:8080/counts" 2>/dev/null) || {
      echo "error: echo's pod $pod did not answer GET /counts" >&2
      return 1
    }
    [ -n "$out" ] || { echo "error: echo's pod $pod has counted nothing" >&2; return 1; }
    all+="$out"$'\n'
  done <<<"$pods"
  printf '%s' "$all" | awk '{ split($2, s, "="); split($3, u, "="); st[$1] += s[2]; un[$1] += u[2] }
    END { for (h in st) printf "%s stamped=%d unstamped=%d\n", h, st[h], un[h] }' | LC_ALL=C sort
}

# echo_sent <host>: the requests on the host that echo answered 200 through the Gateway, by the tally.
echo_sent() {
  [ -f "$RUN_DIR/echo-sent" ] || { printf 0; return; }
  awk -v h="$1" '$1 == h { n += $2 } END { printf "%d", n }' "$RUN_DIR/echo-sent" 2>/dev/null
}

# A suite's undo: one command that puts back what the suite changed in the cluster (its replicas, say). The suite
# sets UNDO when it makes the change and runs undo when it is done with it, on its error paths as well; measure.sh's
# finish runs it on any other exit (an interrupt, or a step that stops the whole run) while the cluster is kept.
# UNDO is cleared once the command has run, not before: an interrupt while it runs leaves it for finish to run again.
UNDO=""
undo() {
  local status=0
  [ -z "$UNDO" ] || eval "$UNDO" || status=$?
  UNDO=""
  return "$status"
}

# processor_replicas <n>: the chart as the measurements run it, but with n processor replicas, and waits until n
# are running and ready and the edge answers 200 on both twins again.
processor_replicas() {
  local live
  measure_chart --set replicas="$1" --wait --timeout 5m >/dev/null 2>&1 &&
    kn rollout status deployment/paztport-processor --timeout=300s >/dev/null || {
    echo "error: the processor did not come up with $1 replica(s)" >&2
    return 1
  }
  for _ in $(seq 1 120); do
    live=$(processor_pods | grep -c . || true)
    [ "$live" = "$1" ] && break
    sleep 1
  done
  [ "$live" = "$1" ] || { echo "error: $live processor pods are running, not $1" >&2; return 1; }
  wait_measure >/dev/null
}

# processor_outcomes: the requests the processor's running pods decided, by outcome, added up over the pods:
# "stamped=<n> refused_route=<n> refused_material=<n> refused_body=<n> refused_error=<n>
# abandoned=<n>". A pod that started again counts from zero, so read processor_restarts beside it.
processor_outcomes() {
  local pod ip text texts="" outcome line="" n
  for pod in $(processor_pods); do
    ip=$(kn get pod "$pod" -o jsonpath='{.status.podIP}')
    text=$(kn exec checks -- curl -sf --max-time 10 "http://$ip:9090/metrics" 2>/dev/null) || {
      echo "error: the processor pod $pod did not answer GET /metrics" >&2
      return 1
    }
    texts+="$text"$'\n'
  done
  for outcome in stamped refused_route refused_material refused_body refused_error abandoned; do
    n=$(metric_sum "$texts" "paztport_edge_requests_total{outcome=\"$outcome\"}")
    line+="$outcome=$n "
  done
  printf '%s\n' "${line% }"
}

# outcomes_added <before> <after>: what processor_outcomes, or envoy_extproc_stats, added between two readings of
# "<name>=<n>" words, as "<name> +<n>" for each name; or, for a counter lower than before, which started again from
# zero in between (a processor pod that started again), "<name> <n> since it started again", as what it added before
# that is lost. The cluster_ counters are one cluster's, which Envoy Gateway may delete and make again (it does when
# the processor has no ready endpoint): when any of them is lower than before, every one of them is printed as
# "<name> <n> since the cluster was made again", since a counter that merely did not fall lost its counts as well.
outcomes_added() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    n = split(a, x, " ")
    for (i = 1; i <= n; i++) { split(x[i], kv, "="); before[kv[1]] = kv[2] }
    n = split(b, y, " ")
    for (i = 1; i <= n; i++) {
      split(y[i], kv, "=")
      name[i] = kv[1]; now[i] = kv[2]
      if (kv[1] ~ /^cluster_/ && kv[2] + 0 < before[kv[1]] + 0) remade = 1
    }
    for (i = 1; i <= n; i++) {
      if (remade && name[i] ~ /^cluster_/) {
        out = out sep name[i] " " now[i] " since the cluster was made again"
      } else if (now[i] + 0 < before[name[i]] + 0) {
        out = out sep name[i] " " now[i] " since it started again"
      } else {
        out = out sep name[i] " " sprintf("%+d", now[i] - before[name[i]])
      }
      sep = ", "
    }
    print out
  }'
}

# processor_restarts: for each processor pod running and not being deleted, its restarts, and how its container
# last ended: "<pod> restarts=<n> last=<reason>@<time>" a line ("last=-" when it never ended).
processor_restarts() {
  local c='.status.containerStatuses[0]' each pod
  each="{.metadata.name} restarts={$c.restartCount}"
  each+=" last={$c.lastState.terminated.reason}@{$c.lastState.terminated.finishedAt}"
  for pod in $(processor_pods); do
    kn get pod "$pod" -o jsonpath="$each{\"\\n\"}" | sed 's/last=@$/last=-/'
  done
}

# envoy_admin: a port-forward to the edge's Envoy's admin port (19000), made once -> ENVOY_ADMIN (its local address).
# The admin port listens on Envoy's own loopback only, so a forward is the one way in.
# A change to the EnvoyProxy can give Envoy a new pod: the forward is made again when its pod is not the one Envoy
# runs in now, or the forward has stopped. A forward made in a subshell (a command substitution) is lost with it, so
# a suite calls envoy_admin in its own shell first, and again after anything that may move Envoy.
ENVOY_ADMIN=""
ENVOY_ADMIN_POD=""
ENVOY_ADMIN_PID=""
envoy_admin() {
  local pod
  pod=$(k -n "$EG_NS" get pods -l "gateway.envoyproxy.io/owning-gateway-name=edge" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}') || return 1
  if [ -n "$ENVOY_ADMIN" ] && [ "$pod" = "$ENVOY_ADMIN_POD" ] && kill -0 "$ENVOY_ADMIN_PID" 2>/dev/null; then
    return 0
  fi
  [ -z "$ENVOY_ADMIN_PID" ] || { kill "$ENVOY_ADMIN_PID" 2>/dev/null; forget "$ENVOY_ADMIN_PID"; }
  forward "$EG_NS" "pod/$pod" 19000
  ENVOY_ADMIN="$FORWARDED"
  ENVOY_ADMIN_POD="$pod"
  ENVOY_ADMIN_PID="${forwards[${#forwards[@]} - 1]}"
}

# forget <pid>: takes a background process that has ended, or been waited for, out of forwards, so that measure.sh's
# finish never signals its pid, which may be another process's by then.
forget() {
  local kept=() p
  for p in ${forwards[@]+"${forwards[@]}"}; do
    [ "$p" = "$1" ] || kept+=("$p")
  done
  forwards=(${kept[@]+"${kept[@]}"})
}

# envoy_routing: how Envoy reaches the backends and the processor, the EnvoyProxy edge's routingType: Endpoint (the
# pods, Envoy Gateway's default when it is unset) or Service (the Service's cluster IP, which kube-proxy balances
# per connection).
envoy_routing() {
  local routing
  routing=$(k -n "$EG_NS" get envoyproxy edge -o jsonpath='{.spec.routingType}') || return 1
  printf '%s' "${routing:-Endpoint}"
}

# envoy_routing_set Endpoint|Service: sets it (Endpoint by removing routingType, as kind/gateway.yaml has it), then
# waits, for up to 120 s, until Envoy's cluster for the processor holds the hosts that routing gives: the processor's
# pod IPs, or its Service's cluster IP. Run it in the suite's own shell, not a subshell (see envoy_admin).
envoy_routing_set() {
  local want hosts
  if [ "$1" = Endpoint ]; then
    if [ -n "$(k -n "$EG_NS" get envoyproxy edge -o jsonpath='{.spec.routingType}')" ]; then
      k -n "$EG_NS" patch envoyproxy edge --type=json -p '[{"op": "remove", "path": "/spec/routingType"}]' \
        >/dev/null || return 1
    fi
  else
    k -n "$EG_NS" patch envoyproxy edge --type=merge -p "{\"spec\": {\"routingType\": \"$1\"}}" >/dev/null || return 1
  fi
  k -n "$EG_NS" rollout status deployment \
    -l "gateway.envoyproxy.io/owning-gateway-name=edge,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
    --timeout=180s >/dev/null || return 1
  for _ in $(seq 1 120); do
    if [ "$1" = Endpoint ]; then
      want=$(kn get pods -l app.kubernetes.io/name=paztport-processor --field-selector=status.phase=Running \
        -o jsonpath='{.items[*].status.podIP}' | tr ' ' '\n' | LC_ALL=C sort | paste -sd ' ' -)
    else
      want=$(kn get service paztport-processor -o jsonpath='{.spec.clusterIP}')
    fi
    # In this shell, so that a new forward, for a new Envoy pod, outlives the reading.
    envoy_admin >/dev/null 2>&1 && hosts=$(processor_hosts 2>/dev/null) || hosts=""
    [ -n "$want" ] && [ "$hosts" = "$want" ] && return 0
    sleep 1
  done
  echo "error: Envoy's cluster for the processor holds [$hosts], not [$want], 120 s after routing to $1" >&2
  return 1
}

# processor_hosts: the hosts of Envoy's cluster for the processor, from its admin port's /clusters, sorted, on one
# line.
processor_hosts() {
  envoy_admin || return 1
  curl -sf --max-time 2 "http://$ENVOY_ADMIN/clusters" |
    sed -n 's|^envoyextensionpolicy/[^:]*paztport-processor[^:]*::\([0-9.]*\):9002::health_flags::.*|\1|p' |
    LC_ALL=C sort -u | paste -sd ' ' -
}

# envoy_host_failed <pod ip>: whether Envoy's active health check has failed the host at that IP, port 9002, of its
# cluster for the processor, from its admin port's /clusters: "yes" (the host's failed_active_health_check flag is
# set), "no" (the host is listed without it, or the cluster lists no host at that address), or "unread" (the admin
# port, or its answer, could not be read, or it held no cluster for the processor). It is the one Envoy pod
# envoy_admin forwards to that is read: each Envoy pod checks the host on its own.
envoy_host_failed() {
  local json
  envoy_admin 2>/dev/null && json=$(curl -sf --max-time 2 "http://$ENVOY_ADMIN/clusters?format=json") ||
    { echo unread; return 0; }
  python3 -c 'import json, re, sys
try:
    clusters = json.load(sys.stdin)["cluster_statuses"]
    seen, failed = False, False
    for c in clusters:
        name = c.get("name", "")
        if not re.match(r"envoyextensionpolicy/.*paztport-processor", name) or ".internal." in name:
            continue
        seen = True
        for h in c.get("host_statuses", []):
            a = h.get("address", {}).get("socket_address", {})
            if a.get("address") == sys.argv[1] and a.get("port_value") == 9002:
                failed = failed or bool(h.get("health_status", {}).get("failed_active_health_check"))
except (ValueError, KeyError, TypeError, AttributeError):
    seen = False
print(("yes" if failed else "no") if seen else "unread")' "$1" <<<"$json"
}

# envoy_extproc_stats: Envoy's counters for the processor: its ext_proc filter's streams (started, failed, timed
# out, and let through for failing open), its cluster's requests refused for a full circuit breaker or timed out,
# and its cluster's connections: none made for want of a healthy processor, failed, or closed by the processor with
# requests on them; and its cluster's active health checks: passed, failed, or failed for want of a connection; as
# "<name>=<n>" words. The ext_proc filter's stats (streams_started, streams_failed, message_timeouts,
# failure_mode_allowed) keep Envoy's names; the cluster's are the harness's labels: cluster_rq_* for Envoy's
# upstream_rq_* counters (active_overflow, pending_overflow, timeout), cluster_cx_* for upstream_cx_*.
envoy_extproc_stats() {
  envoy_admin || return 1
  curl -sf "http://$ENVOY_ADMIN/stats" | awk -F': ' '
    $1 ~ /^http\.[^.]*\.ext_proc\.(streams_started|streams_failed|message_timeouts|failure_mode_allowed)$/ {
      sub(/^http\.[^.]*\.ext_proc\./, "", $1); s[$1] += $2 }
    $1 ~ /^cluster\.envoyextensionpolicy\/.*paztport-processor/ && $1 !~ /\.internal\./ &&
      $1 ~ /\.upstream_rq_(active_overflow|pending_overflow|timeout)$/ {
      sub(/^.*\.upstream_rq_/, "cluster_rq_", $1); s[$1] += $2 }
    $1 ~ /^cluster\.envoyextensionpolicy\/.*paztport-processor/ && $1 !~ /\.internal\./ &&
      $1 ~ /\.upstream_cx_(none_healthy|connect_fail|destroy_remote_with_active_rq)$/ {
      sub(/^.*\.upstream_cx_/, "cluster_cx_", $1); s[$1] += $2 }
    $1 ~ /^cluster\.envoyextensionpolicy\/.*paztport-processor/ && $1 !~ /\.internal\./ &&
      $1 ~ /\.health_check\.(success|failure|network_failure)$/ {
      sub(/^.*\.health_check\./, "hc_", $1); s[$1] += $2 }
    END { for (k in s) printf "%s=%d ", k, s[k] }' | tr ' ' '\n' | LC_ALL=C sort | paste -sd ' ' -
}

# backends_env [file]: the environment of orders' and payment's containers, "<deployment> <name>=<value>" a line in
# their order: as the cluster runs them, or with file, as kind/backends.yaml sets them.
backends_env() {
  local json
  if [ "${1:-}" = file ]; then
    json=$(k create --dry-run=client -o json -f kind/backends.yaml) || return 1
  else
    json=$(kn get deployment orders payment -o json) || return 1
  fi
  json_items <<<"$json" | python3 -c 'import json, sys
for d in json.load(sys.stdin):
    if d.get("kind") == "Deployment" and d["metadata"]["name"] in ("orders", "payment"):
        for e in d["spec"]["template"]["spec"]["containers"][0].get("env", []):
            print("%s %s=%s" % (d["metadata"]["name"], e["name"], e.get("value", "")))'
}

# backends_env_matches: whether orders and payment run exactly kind/backends.yaml's environment; prints what
# differs when they do not. kubectl apply puts back a variable the file sets, but leaves one it does not set (a
# Spring setting a suite added with kubectl set env, say), so this is checked, not assumed.
backends_env_matches() {
  local want got
  want=$(backends_env file) && got=$(backends_env) || return 1
  [ "$want" = "$got" ] && return 0
  echo "error: orders' and payment's environment is not kind/backends.yaml's:" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") |
    sed -n 's/^</  the file has:    /p; s/^>/  the cluster has: /p' >&2
  return 1
}

# echo_unstamped: the behavioural lines at the end of a suite on the twins: echo's counts could be read from every pod;
# echo saw no request without a stamp, and echo-plain none with one; and, for each twin, echo counted no fewer requests
# than it answered 200 through the Gateway by the tally (k6's runs and the waits' probes, since echo's pods started,
# which is within this run: install_measure starts echo again). It may count more: a request it answered whose response
# never came back as a 200 (a client timeout, a reset) is in its count and not in the tally. Returns 1 if any line is
# FAIL.
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

# The users k6 holds for the ceiling suite's open-model runs: a stage offered R requests a second has R x
# POOL_SECONDS users, all of them started before the run (k6 starting users during a run is slow enough to drop
# requests on its own: at 9000/s, with 500 ready and up to 4500 allowed, it dropped about 180 while the p99 was
# 62 ms). By Little's law the pool then runs out only when the requests in flight average more than POOL_SECONDS,
# 100 ms: past any stage that is sustained here (their mean stays well under it, though a sustained stage's p99 has
# reached 87 ms), so a request dropped says that the system held the requests, not that k6 was short of users. At
# the highest stage, 25000/s, that is 2500 users, well within k6's pod (about a quarter of a megabyte a user). Never
# fewer than CEILING_PREALLOC.
CEILING_PREALLOC=500
POOL_SECONDS=0.1

# pool <rate> [least]: the users k6 holds for a run offered rate requests a second: rate x POOL_SECONDS, and never
# fewer than least (CEILING_PREALLOC unless given).
pool() {
  awk -v r="$1" -v s="$POOL_SECONDS" -v p="${2:-$CEILING_PREALLOC}" \
    'BEGIN { n = int(r * s + 0.5); printf "%d", (n > p ? n : p) }'
}

# held_pool <rate> <seconds>: the users k6 holds for a run offered rate requests a second whose requests may each be
# held that long: rate x seconds, and pool's at least.
held_pool() {
  pool "$1" "$(awk -v r="$1" -v s="$2" 'BEGIN { printf "%d", r * s + 0.5 }')"
}

# orders_rate <setting> <value>: sets ORDERS_RATE_USED, the requests a second a suite offers the route orders, and
# prints where it came from: the setting's value, when it is set; else half the highest stage the edge suite
# sustained on orders in this run (edge-rounds), when it ran; else ORDERS_DEFAULT_RATE, the fallback measured on the
# author's machine. Returns 1 for a value that is not a number of requests a second.
orders_rate() {
  local sustained=0
  case "$2" in
    "") ;;
    *[!0-9]* | 0)
      echo "error: $1 is $2, not a number of requests a second" >&2
      return 1
      ;;
    *)
      ORDERS_RATE_USED="$2"
      echo "  the rate on orders: $ORDERS_RATE_USED/s, from $1"
      return 0
      ;;
  esac
  [ ! -f "$RUN_DIR/edge-rounds" ] ||
    sustained=$(awk '$1 == "orders" { s = $4 } END { printf "%d", s }' "$RUN_DIR/edge-rounds")
  if [ "${sustained:-0}" -gt 0 ]; then
    ORDERS_RATE_USED=$((sustained / 2))
    echo "  the rate on orders: $ORDERS_RATE_USED/s, half the highest stage the edge suite sustained there in this" \
      "run ($sustained/s, in edge-rounds)"
  else
    ORDERS_RATE_USED="$ORDERS_DEFAULT_RATE"
    echo "  the rate on orders: $ORDERS_RATE_USED/s, ORDERS_DEFAULT_RATE, the fallback measured on the author's" \
      "machine: this run has no stage the edge suite sustained on orders"
  fi
}

# sustained <route> <replicas>: the median over the ceiling suite's rounds of the highest stage sustained there, or
# 0.
sustained() {
  awk -v r="$1" -v n="$2" '$1 == r && $2 == n { s = $3 } END { printf "%d", s }' "$RUN_DIR/ceiling-sustained"
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

# orders_decided <before> <after>: what orders decided between two readings of backend_reasons, by reason, from its
# request counters: "<reason> <n>" a line, sorted, for each reason it counted more of.
orders_decided() {
  python3 -c 'import collections, re, sys
def read(text):
    out = collections.Counter()
    for line in text.splitlines():
        app, series, count = line.split()
        if app == "orders" and series.startswith("paztport_request"):
            out[dict(re.findall(r"(\w+)=\"([^\"]*)\"", series)).get("reason", "?")] += int(count)
    return out
for reason, n in sorted((read(sys.argv[2]) - read(sys.argv[1])).items()):
    print(reason, n)' "$1" "$2"
}

# orders_counted <before> <n>: backend_reasons, read again for up to 5 s until orders' request counters have added
# n since before: orders counts a request once its response is done, a moment after the client has it.
orders_counted() {
  local after=""
  for _ in $(seq 1 10); do
    after=$(backend_reasons) || return 1
    python3 -c 'import re, sys
def total(text):
    return sum(int(line.split()[2]) for line in text.splitlines()
               if line.startswith("orders paztport_request"))
sys.exit(0 if total(sys.argv[2]) - total(sys.argv[1]) >= int(sys.argv[3]) else 1)' "$1" "$after" "$2" && break
    sleep 0.5
  done
  printf '%s\n' "$after"
}

# orders_traces <since> [by-pod]: orders' trace lines for the requests it received since the time (UTC, to the second,
# as 2026-01-02T03:04:05), from the log files the kind node keeps for every orders pod running: every container's, one
# killed included, and the files the kubelet rotated (past 10 MiB) as well as the current one, which is all kubectl
# logs would read. "PAZTPORT_TRACE request rid=<rid> reason=<reason> ..." a line, as the node's file holds it ("<time>
# stdout F PAZTPORT_TRACE ..."), each after its pod's name with by-pod. Returns 1, saying which, when a pod's log
# files could not be read.
orders_traces() {
  local pod uid logs="$tmp/orders-logs"
  for pod in $(live_pods app=orders); do
    uid=$(kn get pod "$pod" -o jsonpath='{.metadata.uid}') || return 1
    # shellcheck disable=SC2016 # the script runs in the node's shell
    docker exec "$(node_container)" sh -c 'cd "/var/log/pods/$1_$2_$3/orders" || exit 1
      for f in *; do case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac || exit 1; done' sh "$NS" "$pod" "$uid" \
      >"$logs" || {
      echo "error: could not read the log files of orders' pod $pod on the node" >&2
      rm -f "$logs"
      return 1
    }
    awk -v s="$1" -v p="$([ "${2:-}" = by-pod ] && printf '%s ' "$pod")" \
      'substr($1, 1, 19) >= s && index($0, "PAZTPORT_TRACE request") { print p $0 }' "$logs"
  done
  rm -f "$logs"
}

# processor_settled: until every processor pod is running and none is being deleted, and Envoy's cluster for the
# processor holds those pods' addresses and no other, for up to 60 s: a helm upgrade that rolls the processor returns
# while the old pods drain (a pod being deleted is still Running through its preStop and its drain), and a request
# Envoy sends one of them meanwhile is decided on the old pod's routes and material.
processor_settled() {
  local want hosts all live
  envoy_admin || return 1
  for _ in $(seq 1 120); do
    all=$(kn get pods -l app.kubernetes.io/name=paztport-processor -o name | grep -c . || true)
    # The pods running and not being deleted (processor_pods'), by address.
    want=$(kn get pods -l app.kubernetes.io/name=paztport-processor --field-selector=status.phase=Running \
      -o jsonpath='{range .items[*]}{.status.podIP} {.metadata.deletionTimestamp}{"\n"}{end}' |
      awk 'NF == 1 { print $1 }' | LC_ALL=C sort | paste -sd ' ' -)
    live=$(wc -w <<<"$want" | tr -d ' ')
    hosts=$(processor_hosts 2>/dev/null)
    [ -n "$want" ] && [ "$hosts" = "$want" ] && [ "$all" -eq "$live" ] && return 0
    sleep 0.5
  done
  echo "error: the processor's pods did not settle: $all pods, $live running and not being deleted; Envoy's" \
    "cluster for it holds [$hosts], not [$want]" >&2
  return 1
}

# backend_restarts: each orders and payment pod's restarts, "<pod> restarts=<n>; ..." on one line.
backend_restarts() {
  kn get pods -l 'app in (orders,payment)' \
    -o jsonpath='{range .items[*]}{.metadata.name} restarts={.status.containerStatuses[0].restartCount}{"\n"}{end}' |
    awk 'NF { printf "%s%s %s", sep, $1, $2; sep = "; " } END { print "" }'
}
