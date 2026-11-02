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
  for word in java-mesh agents-mcp test bench "macOS and Linux; on Windows use WSL"; do
    grep -qF "$word" <<<"$out" || return 1
  done
}

# basic_tools: prints a new directory holding everything ./run needs before it checks for node or mvn, and
# nothing else, so with it as PATH node is genuinely absent, and mvn too unless one is faked.
basic_tools() {
  local bin tool found
  bin="$(mktemp -d)"
  for tool in bash env dirname uname sort head sed grep awk cut tr cat printf; do
    found="$(command -v "$tool" 2>/dev/null)" && [ -x "$found" ] && ln -s "$found" "$bin/$tool"
  done
  echo "$bin"
}

# missing_stops_early <tool> <arguments> [mvn -v text]: with only the basic tools on PATH, and an mvn that prints
# the given text if one is given, ./run with <arguments> (split on spaces) prints one 'missing: <tool>' line and
# exits 1.
missing_stops_early() {
  local bin out status args
  read -ra args <<<"$2"
  bin="$(basic_tools)"
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
check "bench with no java at Maven's JDK prints one 'missing: java' line and exits 1" \
  missing_stops_early java bench "Java version: 25.0.1, vendor: Test, runtime: /nonexistent"
check "a clean clone passes ./run test" clean_clone_passes_run_test

[ "$failures" -eq 0 ] || { echo "$failures failed"; exit 1; }
echo "all passed"
