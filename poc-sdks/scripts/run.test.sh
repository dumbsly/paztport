#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Tests for the ./run front door: usage, the missing-prerequisite path, and a clean clone that passes
# ./run test (which proves the file: links resolve with nothing pre-installed). Runs no Docker and no
# model. The clean-clone case installs and runs every suite, so it takes minutes.
set -uo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
failures=0

check() { # name, then a command that succeeds when the case passes
  local name="$1"; shift
  if "$@"; then echo "ok   - $name"; else echo "FAIL - $name"; failures=$((failures + 1)); fi
}

help_lists_subcommands() {
  local out
  out="$("$repo/run" --help)" || return 1
  for word in java-mesh agents-mcp envoy-gateway test bench "macOS and Linux; on Windows use WSL"; do
    grep -qF "$word" <<<"$out" || return 1
  done
}

# basic_tools [tool...]: prints a new directory holding everything ./run needs before it checks for node or mvn,
# and the named tools, and nothing else, so with it as PATH node is genuinely absent, and mvn too unless one is
# faked.
basic_tools() {
  local bin tool found
  bin="$(mktemp -d)"
  for tool in bash env dirname uname sort head sed grep awk cut tr cat printf "$@"; do
    found="$(command -v "$tool" 2>/dev/null)" && [ -x "$found" ] && ln -s "$found" "$bin/$tool"
  done
  echo "$bin"
}

# missing_stops_early [-with <tools>] <tool> <arguments> [mvn -v text]: with only the basic tools on PATH, the
# tools after -with too (split on spaces), and an mvn that prints the given text if one is given, ./run with
# <arguments> (split on spaces) prints one 'missing: <tool>' line and exits 1.
missing_stops_early() {
  local bin out status args with=()
  if [ "$1" = -with ]; then read -ra with <<<"$2"; shift 2; fi
  read -ra args <<<"$2"
  # The guarded expansion: an empty array under set -u is an error in bash before 4.4, which macOS ships.
  bin="$(basic_tools ${with[@]+"${with[@]}"})"
  if [ $# -ge 3 ]; then
    printf '%s\n' "$3" >"$bin/mvn-v.txt"
    printf '#!%s\ncat "%s"\n' "$bin/bash" "$bin/mvn-v.txt" >"$bin/mvn"
    chmod +x "$bin/mvn"
  fi
  out="$(PATH="$bin" "$bin/bash" "$repo/run" "${args[@]}" 2>&1)"; status=$?
  rm -rf "$bin"
  [ "$status" -eq 1 ] && grep -q "^missing: $1 " <<<"$out" && [ "$(wc -l <<<"$out")" -eq 1 ]
}

# help_after <command>: with only the basic tools on PATH, ./run <command> -h prints the usage and exits 0, so it
# stops before the command checks for anything.
help_after() {
  local bin out status
  bin="$(basic_tools)"
  out="$(PATH="$bin" "$bin/bash" "$repo/run" "$1" -h 2>&1)"; status=$?
  rm -rf "$bin"
  [ "$status" -eq 0 ] && grep -q "^Usage: " <<<"$out"
}

# envoy_missing <tool> [fake kubectl version text]: with fake mvn (Java 25), docker, go, kind and, when the text is
# given, kubectl, that pass their checks, ./run envoy-gateway prints one 'missing: <tool>' line and exits 1: the
# earlier checks pass, and the later ones are not reached.
envoy_missing() {
  local bin out status
  bin="$(basic_tools)"
  printf '#!%s\necho "Java version: 25.0.1, vendor: Test, runtime: /nonexistent"\n' "$bin/bash" >"$bin/mvn"
  printf '#!%s\nexit 0\n' "$bin/bash" >"$bin/docker"
  printf '#!%s\necho "go version go99.0 linux/amd64"\n' "$bin/bash" >"$bin/go"
  chmod +x "$bin/mvn" "$bin/docker" "$bin/go"
  if [ "$1" != kind ]; then
    printf '#!%s\necho "kind v0.33.0 go1.27.0 linux/amd64"\n' "$bin/bash" >"$bin/kind"
    chmod +x "$bin/kind"
  fi
  if [ $# -ge 2 ]; then
    printf '#!%s\necho "%s"\n' "$bin/bash" "$2" >"$bin/kubectl"
    chmod +x "$bin/kubectl"
  fi
  out="$(PATH="$bin" "$bin/bash" "$repo/run" envoy-gateway 2>&1)"; status=$?
  rm -rf "$bin"
  [ "$status" -eq 1 ] && grep -q "^missing: $1 " <<<"$out" && [ "$(wc -l <<<"$out")" -eq 1 ]
}

# material_refuses <phrase> <arguments...>: material.sh run with HOME set to a scratch directory holding a marker
# file, and the arguments (the word @HOME@ standing for that directory), exits non-zero, says <phrase>, and leaves the
# marker and the directory 'taken' alone. Asserting the phrase makes the case fail when the guard is missing, whether
# or not the jars are built, since a missing jar also exits non-zero without deleting anything.
material_refuses() {
  local work status out phrase="$1" args=() arg ok=0
  shift
  work="$(mktemp -d)"
  mkdir "$work/taken" "$work/home"
  touch "$work/taken/keep" "$work/home/keep"
  for arg in "$@"; do args+=("${arg//@HOME@/$work/home}"); done
  out="$(cd "$work" && HOME="$work/home" "$repo/poc-demos/envoy-gateway/material.sh" "${args[@]}" 2>&1)"; status=$?
  [ "$status" -ne 0 ] && grep -qF -- "$phrase" <<<"$out" && [ -e "$work/taken/keep" ] && [ -e "$work/home/keep" ] || ok=1
  rm -rf "$work"
  return "$ok"
}

no_argument_prints_usage() {
  "$repo/run" | grep -q "Usage"
}

clean_clone_passes_run_test() {
  local work status
  work="$(mktemp -d)"
  git clone --quiet "$repo" "$work/paztport" || { rm -rf "$work"; return 1; }
  (cd "$work/paztport" && ./run test)
  status=$?
  rm -rf "$work"
  return "$status"
}

check "--help lists the subcommands and platforms" help_lists_subcommands
check "no argument prints usage" no_argument_prints_usage
check "test -h prints usage" help_after test
check "java-mesh -h prints usage" help_after java-mesh
check "agents-mcp -h prints usage" help_after agents-mcp
check "a PATH without node prints one 'missing: node' line and exits 1" missing_stops_early node agents-mcp
check "bench without mvn prints one 'missing: mvn' line and exits 1" missing_stops_early mvn bench
check "bench -h goes to bench, which without mvn prints one 'missing: mvn' line" missing_stops_early mvn "bench -h"
check "test without unzip prints one 'missing: unzip' line and exits 1" missing_stops_early unzip test
# The jar check's unzip is checked first, so this case has one.
check "test without go prints one 'missing: go' line and exits 1" missing_stops_early -with unzip go test
# The processor's checks need staticcheck; unzip and go are checked before it, so this case has both.
check "test without staticcheck prints one 'missing: staticcheck' line and exits 1" \
  missing_stops_early -with "unzip go" staticcheck test
check "bench with no java at Maven's JDK prints one 'missing: java' line and exits 1" \
  missing_stops_early java bench "Java version: 25.0.1, vendor: Test, runtime: /nonexistent"
check "envoy-gateway -h prints usage" help_after envoy-gateway
check "envoy-gateway without kind prints one 'missing: kind' line and exits 1" envoy_missing kind
check "envoy-gateway with a kubectl below 1.35 prints one 'missing: kubectl' line and exits 1" \
  envoy_missing kubectl "Client Version: v1.34.9"
check "material.sh will not write over an existing directory" material_refuses "exists; the cluster's keys" taken
check "material.sh will not take an empty directory name, with or without --fresh" bash -c \
  "$(declare -f material_refuses); repo='$repo'; material_refuses 'is empty' '' && material_refuses 'is empty' --fresh ''"
check "material.sh --fresh will not delete /" material_refuses "will not delete" --fresh /
check "material.sh --fresh will not delete \$HOME" material_refuses "will not delete" --fresh @HOME@
check "material.sh --fresh will not delete a parent of \$HOME" material_refuses "will not delete" --fresh @HOME@/..
check "a clean clone passes ./run test" clean_clone_passes_run_test

[ "$failures" -eq 0 ] || { echo "$failures failed"; exit 1; }
echo "all passed"
