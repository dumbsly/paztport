# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# What the measurement suites share: the k6 runs, their alternation and summaries, error windows, the processor's
# pods and the kind node, and the reset to the baseline every suite starts from. measure.sh sources it after
# lib.sh, and sets RUN_DIR (this run's results), tmp (a scratch directory) and forwards (port-forwards to kill).
# shellcheck shell=bash

# k6, pinned by the digest of its index (k6 2.2.0, released 2026-08-10).
K6_IMAGE=docker.io/grafana/k6:2.2.0@sha256:9bd01d6941fca969cb61bb57d2da5ee9b385fe2aa8881df3798c196564d6ace6
# The twin routes' hosts (kind/measure.yaml): the processor is attached to the first, never to the second.
ECHO_HOST=echo.example
PLAIN_HOST=echo-plain.example
# The HTTPRoutes of the baseline; baseline_reset deletes any other.
BASE_ROUTES="orders orders-unmapped echo echo-plain"

# measure_chart [helm args...]: the chart as the measurements run it: orders and echo mapped to the receiver
# orders, the autoscaler off and two replicas, unless the args set others.
measure_chart() {
  install_chart --set 'routes[1].httpRoute=echo' --set 'routes[1].receiver=orders' \
    --set autoscaling.enabled=false --set replicas=2 "$@"
}

load_echo_image() {
  kind load docker-image --name "$CLUSTER" paztport-echo:dev
}

# install_measure: what the measurements add to the cluster up made: echo in the chart's routes first, then echo,
# its twin routes and their BackendTrafficPolicy, and k6's script.
install_measure() {
  quietly "loading the echo image into kind" load_echo_image
  quietly "mapping echo in the chart" measure_chart --wait --timeout 5m
  quietly "applying echo and the twin routes" apply_routes kind/measure.yaml
  quietly "loading k6's script" apply_files "$NS" configmap k6-edge "edge.js=$here/measure/k6/edge.js"
  quietly "waiting for the twin routes" wait_measure
}

# edge_status <host>: the status of one POST /orders through the Gateway for the host, from the pod checks. A 200
# on a twin's host is a request echo answered, and goes into the tally echo's counts are checked against.
edge_status() {
  local code
  code=$(kn exec checks -- curl -s -o /dev/null -w '%{http_code}' -X POST -H "host: $1" \
    -H 'content-type: application/json' -d '{}' "$EDGE/orders" 2>/dev/null)
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

# How long k6_run waits beyond a run's own length: edge.js's gracefulStop (15 s), and the pod's scheduling, image
# pull and start.
K6_MARGIN=120

# k6_run <name> <VAR=value>...: runs measure/k6/edge.js in the Job k6-<name>, with the settings given (the last of
# a name wins), and waits for it, for the run's length and K6_MARGIN more; prints its RESULT line, writes its FAIL
# lines to $RUN_DIR/<name>.fails, and the expected status and the RESULT line to $RUN_DIR/<name>.result (for
# window), adds the 200s on a twin's host to echo's tally, and deletes the Job. Returns 1, with what it saw, when
# the run timed out (or its pod never started) or printed no RESULT line. Warns, without failing, when the Job
# failed though k6 printed a RESULT line, and when the RESULT's statuses do not sum to its requests.
k6_run() {
  local name="$1" job="k6-$1" kv later seen env="" log state i j expect=200 result duration="" stages="" host=""
  local wait phase
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
            limits: {cpu: "2", memory: 2Gi}
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
  wait=$(run_seconds "$duration" "$stages") || return 1
  wait=$((wait + K6_MARGIN))
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
        "" | Pending*) echo "error: the k6 run $name timed out after $wait s: its pod never started (${phase:-no pod})" >&2 ;;
        *) echo "error: the k6 run $name timed out after $wait s, its pod ${phase% }; its last output:" >&2
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
      "$(grep -v '^FAIL \|^RESULT ' "$log" | tail -n 3 | tr '\n' ' ')" >&2 ;;
  esac
  python3 -c 'import json, sys
r = json.loads(sys.argv[2][len("RESULT "):])
total = sum(r["status"].values())
if total != r["reqs"]:
    print("warning: the k6 run %s: its statuses sum to %d, not to its %d requests" % (sys.argv[1], total, r["reqs"]))' \
    "$name" "$result" >&2
  printf '%s %s\n' "$expect" "$result" >"$RUN_DIR/$name.result"
  [ -z "$host" ] || echo_tally "$host" "$(printf '%s' "$result" | sed -n 's/.*"200":\([0-9]*\).*/\1/p')"
  printf '%s\n' "$result"
}

# alternate <name> <labelA> <setupA> <labelB> <setupB> <VAR=value>...: compares two setups like for like. Each
# setup is a command, evaluated before each run of its label, that may set RUN_VARS (an array) to that label's own
# k6 settings. First a warm-up of each label (WARMUP long, discarded); then ROUNDS rounds of one run of each
# (DURATION long), the leading label alternating from round to round. Prints each run, then summary.py's medians,
# spread and what B adds to A.
alternate() {
  local name="$1" la="$2" sa="$3" lb="$4" sb="$5" round label setup line order
  shift 5
  local runs="$RUN_DIR/$name.runs"
  : >"$runs"
  for label in "$la" "$lb"; do
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
      printf '%s %s\n' "$label" "$line" >>"$runs"
    done
  done
  python3 "$here/measure/summary.py" medians "$runs" "$la" "$lb"
}

# window <fails file>: the responses other than the expected that a run saw: how many, the first and the last, and
# the span between them; and, when k6 listed fewer of them than the run counted (it lists at most 20000), that the
# window covers only those listed.
window() {
  python3 "$here/measure/summary.py" window "$1"
}

# live_pods <selector>: the pods the selector picks that are running and not being deleted, one a line.
live_pods() {
  kn get pods -l "$1" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp}{"\n"}{end}' | awk 'NF == 1 { print $1 }'
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

# netem_clear: removes a netem queue from each processor pod's interface, and prints how many it removed.
netem_clear() {
  local pod n=0 qdiscs
  for pod in $(processor_pods); do
    qdiscs=$(pod_tc "$pod" qdisc show dev eth0) || return 1
    if grep -q netem <<<"$qdiscs"; then
      pod_tc "$pod" qdisc del dev eth0 root || return 1
      n=$((n + 1))
    fi
  done
  echo "$n"
}

# The files each pod mounts from out/, as "<volume>/<file>=<path in out/>", and the volumes they are in.
ORDERS_FILES="keys/orders.key=keys/orders.key keys/keyring.json=keys/keyring.json keys/policy.pub=keys/policy.pub
  policy/root.json=policy/root.json policy/proofs-orders.json=policy/proofs-orders.json tls/orders.crt=keys/tls/orders.crt
  tls/orders.key=keys/tls/orders.key tls/ca.crt=keys/tls/ca.crt"
PAYMENT_FILES="keys/payment.key=keys/payment.key keys/keyring.json=keys/keyring.json keys/policy.pub=keys/policy.pub
  policy/root.json=policy/root.json tls/payment.crt=keys/tls/payment.crt tls/payment.key=keys/tls/payment.key
  tls/ca.crt=keys/tls/ca.crt"
# routes.txt, in the processor's policy volume, is the chart's own, not material.
PROCESSOR_FILES="key/edge.key=keys/edge.key tls/tls.crt=keys/tls/paztport-processor.crt
  tls/tls.key=keys/tls/paztport-processor.key ca/ca.crt=keys/tls/ca.crt policy/policy.pub=keys/policy.pub
  policy/keyring-0.json=keys/keyring.json policy/root-0.json=policy/root.json policy/proofs-edge.json=policy/proofs-edge.json"

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
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^</  out\/ has:   /p; s/^>/  pod has:    /p' >&2
      fi
    done
  done
  [ "$bad" -eq 0 ]
}

# baseline_reset: puts the cluster back as every suite starts from it, and prints that state. Any HTTPRoute but
# orders, orders-unmapped, echo and echo-plain is taken off the Gateway first, then the chart is the measurements'
# (two replicas, the autoscaler off), echo and its twin routes and the backends are as their files have them (enforce
# mode), no processor pod has a netem queue (cleared first of all, since a delayed pod may not be ready, and every
# wait would then time out), and everything is ready. A step that fails stops the whole run, and so
# does material in any pod that is not out/'s: a suite that broke must not leave the next one measuring something
# else. Nothing is rolled when nothing changed.
baseline_reset() {
  local route name netem modes hpa replicas routes
  netem=$(netem_clear) || { echo "error: could not read or clear the processor pods' queues" >&2; exit 1; }
  for route in $(kn get httproutes -o name); do
    name="${route#*/}"
    case " $BASE_ROUTES " in
      *" $name "*) ;;
      *) quietly "deleting the route $name" kn delete httproute "$name" ;;
    esac
  done
  quietly "resetting the chart" measure_chart --wait --timeout 5m
  quietly "resetting echo and the twin routes" apply_routes kind/measure.yaml
  quietly "resetting the backends" k apply -f kind/backends.yaml
  quietly "waiting for the baseline" wait_measure
  material_matches || { echo "error: the cluster's material is not out/'s; stopping" >&2; exit 1; }
  modes=$(kn get deployment orders payment \
    -o jsonpath='{range .items[*]}{.metadata.name}={.spec.template.spec.containers[0].env[?(@.name=="PAZTPORT_MODE")].value} {end}')
  hpa=$(kn get hpa -o name | grep -c . || true)
  replicas=$(kn get deployment paztport-processor -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')
  routes=$(kn get httproutes -o jsonpath='{.items[*].metadata.name}')
  echo "  baseline: processor $replicas ready, $hpa autoscaler(s); ${modes% }; routes $routes;" \
    "netem removed from $netem pod(s), none left; material as out/'s in $MATERIAL_PODS pods"
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
