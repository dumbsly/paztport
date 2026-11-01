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

# missing_stops_early <tool> <command>: with only the basic tools on PATH, <command> prints one 'missing: <tool>'
# line and exits 1.
missing_stops_early() {
  local bin out status
  bin="$(mktemp -d)"
  # Everything ./run needs before it checks for node or mvn, and nothing else, so both are genuinely absent.
  for tool in bash env dirname uname sort head sed grep awk cut tr cat printf; do
    local found
    found="$(command -v "$tool" 2>/dev/null)" && [ -x "$found" ] && ln -s "$found" "$bin/$tool"
  done
  out="$(PATH="$bin" "$bin/bash" "$repo/run" "$2" 2>&1)"; status=$?
  rm -rf "$bin"
  [ "$status" -eq 1 ] && grep -q "^missing: $1 " <<<"$out" && [ "$(wc -l <<<"$out")" -eq 1 ]
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
check "a PATH without node prints one 'missing: node' line and exits 1" missing_stops_early node agents-mcp
check "bench without mvn prints one 'missing: mvn' line and exits 1" missing_stops_early mvn bench
check "a clean clone passes ./run test" clean_clone_passes_run_test

[ "$failures" -eq 0 ] || { echo "$failures failed"; exit 1; }
echo "all passed"
