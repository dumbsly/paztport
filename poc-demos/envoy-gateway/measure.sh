#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The Envoy Gateway proof of concept's measurements, on a kind cluster of their own.
#
#   ./run envoy-gateway measure [--keep] [suite...]    builds the jars and the keys, then runs this
#   measure.sh [--keep] [suite...]                      makes the cluster, runs the suites, and deletes the cluster
#   measure.sh --check [--keep] [suite...]              only checks the arguments
#   measure.sh --reuse [suite...]                       runs the suites on the cluster an earlier --keep run left up
#
# It refuses to run while the cluster exists: it makes its own, with envoy-gateway.sh up, and adds the upstream
# echo and its twin routes (kind/measure.yaml). With --reuse it does the opposite: it refuses unless the cluster
# exists, makes nothing (the images and out/ are the ones that cluster was made with), adds echo and its twin routes
# again, and leaves the cluster up at the end, as --keep does; each run has a results directory of its own. Then it
# runs the suites named, or every one, in the order below, each from the same baseline (measure/common.sh's
# baseline_reset), and deletes the cluster at the end, unless --keep. What it prints, and each run's files, go to
# measurements/<UTC time>/, beside out/ and not in it: out/ is material, which material.sh --fresh makes again (and
# ./run envoy-gateway measure runs it), while a run's results cannot be made again, so nothing here deletes them.
# Every number is indicative: one kind node on this machine runs Envoy, the processor, the backends and k6 alike.
#
#   ROUNDS (3), DURATION (20s), WARMUP (10s) and VUS (10) set the runs: see measure/common.sh's alternate.
#   LOAD_RATE_SMALL (1000) and LOAD_RATE_LARGE (500) are the requests a second the load suite offers each twin,
#   with the small and the large body.
#   CEILING_STAGES_1, CEILING_STAGES_2 and CEILING_STAGES_4 are the ceiling suite's stages, in requests a second,
#   with that many processor replicas, and CEILING_ROUNDS (3) how many times it ramps through them on each twin;
#   SATURATION_DURATION (60s) is each of its saturation runs, and MEMORY_VUS (10 25 50 100) its memory steps: see
#   measure/load.sh.
#   EDGE_RATE (500) is the requests a second the edge suite offers each side, EDGE_WARMUP (30s) the discarded
#   warm-up after each rollout, EDGE_STAGES its stages on the route orders, in requests a second, and
#   EDGE_OVERLOAD_RATE (3000) its overload stage there.
#   FAILURE_RATE is the requests a second the failure suite offers echo: unset, half the median the ceiling suite
#   measured on echo with two processor replicas, when it ran in the same run, or else FAILURE_DEFAULT_RATE (5000,
#   half the 10000/s that median was on this machine); FAILURE_ORDERS_RATE is the rate on the route orders. See
#   measure/failure.sh.
#   CHANGE_RATE is the requests a second the route and rotation suites offer the route orders throughout each
#   change (each step's warm-up says when the edge does not hold it); CHANGE_NEW_RATE (50) is the small fixed rate
#   they offer a route they add.
#   FAILURE_ORDERS_RATE and CHANGE_RATE, unset, are half the highest stage the edge suite sustained on orders in the
#   same run, when it ran, or else ORDERS_DEFAULT_RATE (1000), a fallback measured on the author's machine: half the
#   2000/s stage the edge suite sustained there; each suite prints which it used.
#   PAZTPORT_JAVA names the java that runs the policy tool for the material the route and rotation suites make (as
#   for material.sh); otherwise java on the PATH. See measure/change.sh.
#
# Like envoy-gateway.sh, it needs the jars built and out/ made (material.sh); nothing is pushed anywhere, and every
# kubectl and helm call names the cluster's own context.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$here" || exit 1
self="poc-demos/envoy-gateway/measure.sh"

ROUNDS="${ROUNDS:-3}"
DURATION="${DURATION:-20s}"
WARMUP="${WARMUP:-10s}"
VUS="${VUS:-10}"
LOAD_RATE_SMALL="${LOAD_RATE_SMALL:-1000}"
LOAD_RATE_LARGE="${LOAD_RATE_LARGE:-500}"
CEILING_STAGES_1="${CEILING_STAGES_1:-2000 4000 6000 7000 8000 9000 10000 12000}"
CEILING_STAGES_2="${CEILING_STAGES_2:-4000 8000 10000 12000 14000 16000 18000 20000}"
CEILING_STAGES_4="${CEILING_STAGES_4:-8000 12000 14000 16000 18000 20000 22000 25000}"
CEILING_ROUNDS="${CEILING_ROUNDS:-3}"
SATURATION_DURATION="${SATURATION_DURATION:-60s}"
MEMORY_VUS="${MEMORY_VUS:-10 25 50 100}"
EDGE_RATE="${EDGE_RATE:-500}"
EDGE_WARMUP="${EDGE_WARMUP:-30s}"
EDGE_STAGES="${EDGE_STAGES:-250 500 750 1000 1250 1500 2000 3000}"
EDGE_OVERLOAD_RATE="${EDGE_OVERLOAD_RATE:-3000}"
FAILURE_RATE="${FAILURE_RATE:-}"
FAILURE_DEFAULT_RATE="${FAILURE_DEFAULT_RATE:-5000}"
FAILURE_ORDERS_RATE="${FAILURE_ORDERS_RATE:-}"
CHANGE_RATE="${CHANGE_RATE:-}"
ORDERS_DEFAULT_RATE="${ORDERS_DEFAULT_RATE:-1000}"
CHANGE_NEW_RATE="${CHANGE_NEW_RATE:-50}"
# Every suite, in the order they run; a suite is there once a file in measure/ defines suite_<name>.
ORDER="load ceiling edge failure gotchas observe rollout route rotation"

# shellcheck source=measure/common.sh
. measure/common.sh
for file in measure/*.sh; do
  # shellcheck disable=SC1090 # the suites' files
  [ "$file" = measure/common.sh ] || . "$file"
done

suites() {
  local s
  for s in $ORDER; do
    if declare -F "suite_$s" >/dev/null; then echo "$s"; fi
  done
}

usage() {
  echo "usage: $self [--check] [--keep | --reuse] [suite...]; the suites: $(suites | paste -sd " " -)"
}

keep=""
check=""
reuse=""
wanted=" "
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    --check) check=1 ;;
    --reuse) reuse=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      if ! suites | grep -qxF -- "$arg"; then
        echo "measure.sh: no suite $arg" >&2
        usage >&2
        exit 2
      fi
      wanted+="$arg "
      ;;
  esac
done
selected=""
for s in $(suites); do
  if [ "$wanted" = " " ] || [ "${wanted#* "$s" }" != "$wanted" ]; then selected+="$s "; fi
done
if [ -n "$reuse" ] && [ -n "$keep" ]; then
  echo "measure.sh: --reuse leaves the cluster up already; it takes no --keep" >&2
  usage >&2
  exit 2
fi
[ -z "$check" ] || exit 0

if [ -n "$reuse" ]; then
  cluster_exists || {
    echo "measure.sh --reuse: there is no cluster $CLUSTER to run on; a run with --keep leaves one" >&2
    exit 1
  }
  keep=1
elif cluster_exists; then
  echo "the cluster $CLUSTER is up already; $self makes its own: remove it with" \
    "poc-demos/envoy-gateway/envoy-gateway.sh down, or run on it with --reuse" >&2
  exit 1
fi
[ -d "$KEYS" ] && [ -d "$POLICY" ] || { echo "no keys in $here/out: run material.sh first" >&2; exit 1; }

RUN_DIR="$here/measurements/$(date -u +%Y%m%dT%H%M%SZ)"
# A directory of its own, never one an earlier run made, so that no run reads or writes another's results, or the
# material its suites made.
mkdir -p "${RUN_DIR%/*}" && mkdir "$RUN_DIR" || {
  echo "measure.sh: could not make $RUN_DIR as a new directory" >&2
  exit 1
}
tmp="$(mktemp -d)"
forwards=()
made=""

finish() {
  local status=$?
  [ ! -e /dev/fd/9 ] || exec >&9 2>&9
  [ ${#forwards[@]} -eq 0 ] || kill "${forwards[@]}" 2>/dev/null
  # A suite that stopped half-way puts back what it changed, so that a kept cluster is left as the baseline.
  if [ -n "$made" ] && [ -n "$keep" ] && [ -n "$UNDO" ]; then
    echo "== putting back what the suite changed: $UNDO"
    undo
  fi
  rm -rf "$tmp"
  if [ -n "$made" ]; then
    if [ -n "$keep" ]; then
      echo "The cluster is still up (kubectl context $CTX); remove it with" \
        "poc-demos/envoy-gateway/envoy-gateway.sh down"
    else
      echo "== removing the cluster"
      bash "$here/envoy-gateway.sh" down
    fi
  fi
  echo "The results are in ${RUN_DIR#"$repo"/}"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM

# Everything printed goes to the run's log as well. tee ignores an interrupt, which a terminal sends the whole
# process group, and a TERM to the group, so that it outlives this shell and keeps what finish prints while it puts
# the cluster back.
exec > >(trap '' INT TERM && exec tee "$RUN_DIR/measure.log") 2>&1
# The log, kept as fd 9 for finish: an interrupt that comes while a function runs with its output redirected (to
# /dev/null, say) runs finish with that redirection still in place.
exec 9>&1
# On macOS, the host must not sleep while a run measures: a run across a sleep measures nothing (run_paced fails it).
# caffeinate, which macOS has built in, holds the assertion until this shell exits.
if command -v caffeinate >/dev/null 2>&1; then
  caffeinate -i -w "$$" >/dev/null 2>&1 9>&- &
  disown "$!"
  echo "the host is kept from idle sleep for the run (caffeinate -i)"
fi

echo "== measuring the Envoy Gateway edge, $(date -u +%Y-%m-%dT%H:%M:%SZ): suites ${selected% }"
docker info --format '{{.NCPU}} {{.MemTotal}} {{.OperatingSystem}}' 2>/dev/null |
  awk '{ printf "machine: Docker with %d CPUs and %.1f GiB of memory (%s)\n", $1, $2 / 1073741824,
    substr($0, index($0, $3)) }'
echo "Every number is indicative: one kind node on this machine runs Envoy, the processor, the backends and k6."
if [ -n "$reuse" ]; then
  echo "== on the cluster $CLUSTER an earlier run left up (--reuse)"
  made=1
else
  echo "== building the echo image"
  quietly "building the echo image" docker build -q -f "$repo/poc-demos/envoy-gateway/processor/Dockerfile" \
    --target echo -t paztport-echo:dev "$repo"
  made=1
  bash "$here/envoy-gateway.sh" up || exit 1
fi
echo "== echo, its twin routes, and k6's script"
install_measure

failed=""
for s in $selected; do
  echo ""
  "suite_$s" || failed+="$s "
done
echo ""
if [ -n "$failed" ]; then
  echo "== done; these suites failed: ${failed% }"
  exit 1
fi
echo "== done: ${selected% }"
