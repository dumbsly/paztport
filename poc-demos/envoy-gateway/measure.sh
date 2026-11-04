#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The Envoy Gateway proof of concept's measurements, on a kind cluster of their own.
#
#   ./run envoy-gateway measure [--keep] [suite...]    builds the jars and the keys, then runs this
#   measure.sh [--keep] [suite...]                      makes the cluster, runs the suites, and deletes the cluster
#   measure.sh --check [--keep] [suite...]              only checks the arguments
#
# It refuses to run while the cluster exists: it makes its own, with envoy-gateway.sh up, and adds the upstream
# echo and its twin routes (kind/measure.yaml). Then it runs the suites named, or every one, in the order below,
# each from the same baseline (measure/common.sh's baseline_reset), and deletes the cluster at the end, unless
# --keep. What it prints, and each run's files, go to out/measurements/<UTC time>/. Every number is indicative: one
# kind node on this machine runs Envoy, the processor, the backends and k6 alike.
#
#   ROUNDS (3), DURATION (20s), WARMUP (10s) and VUS (10) set the runs: see measure/common.sh's alternate.
#   LOAD_RATE_SMALL (1000) and LOAD_RATE_LARGE (500) are the requests a second the load suite offers each twin,
#   with the small and the large body.
#   CEILING_STAGES_1, CEILING_STAGES_2 and CEILING_STAGES_4 are the ceiling suite's stages, in requests a second,
#   with that many processor replicas; SATURATION_DURATION (60s) is each of its saturation runs, and MEMORY_VUS
#   (10 25 50 100) its memory steps: see measure/load.sh.
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
SATURATION_DURATION="${SATURATION_DURATION:-60s}"
MEMORY_VUS="${MEMORY_VUS:-10 25 50 100}"
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
  echo "usage: $self [--check] [--keep] [suite...]; the suites: $(suites | paste -sd " " -)"
}

keep=""
check=""
wanted=" "
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    --check) check=1 ;;
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
[ -z "$check" ] || exit 0

if cluster_exists; then
  echo "the cluster $CLUSTER is up already; $self makes its own: remove it with" \
    "poc-demos/envoy-gateway/envoy-gateway.sh down" >&2
  exit 1
fi
[ -d "$KEYS" ] && [ -d "$POLICY" ] || { echo "no keys in $here/out: run material.sh first" >&2; exit 1; }

RUN_DIR="$here/out/measurements/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN_DIR" || exit 1
tmp="$(mktemp -d)"
forwards=()
made=""

finish() {
  local status=$?
  [ ${#forwards[@]} -eq 0 ] || kill "${forwards[@]}" 2>/dev/null
  # A suite that stopped half-way puts back what it changed, so that a kept cluster is left as the baseline.
  if [ -n "$made" ] && [ -n "$keep" ] && [ -n "$UNDO" ]; then
    echo "== putting back what the suite changed: $UNDO"
    undo
  fi
  rm -rf "$tmp"
  if [ -n "$made" ]; then
    if [ -n "$keep" ]; then
      echo "The cluster is still up (kubectl context $CTX); remove it with poc-demos/envoy-gateway/envoy-gateway.sh down"
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

# Everything printed goes to the run's log as well.
exec > >(tee "$RUN_DIR/measure.log") 2>&1

echo "== measuring the Envoy Gateway edge, $(date -u +%Y-%m-%dT%H:%M:%SZ): suites ${selected% }"
docker info --format '{{.NCPU}} {{.MemTotal}} {{.OperatingSystem}}' 2>/dev/null |
  awk '{ printf "machine: Docker with %d CPUs and %.1f GiB of memory (%s)\n", $1, $2 / 1073741824, substr($0, index($0, $3)) }'
echo "Every number is indicative: one kind node on this machine runs Envoy, the processor, the backends and k6."
echo "== building the echo image"
quietly "building the echo image" docker build -q -f "$repo/poc-demos/envoy-gateway/processor/Dockerfile" \
  --target echo -t paztport-echo:dev "$repo"
made=1
bash "$here/envoy-gateway.sh" up || exit 1
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
