#!/usr/bin/env bash
# Fails if a tracked file names the private workspace or the process artefacts (its folder, the tool that
# drives the work, the design-document folders). The repo never names them. Case does not matter.
# Each name is written with one letter in a bracket, so this file does not contain the names it looks for
# and needs no exclusion of its own.
set -euo pipefail
cd "$(dirname "$0")/../.."

# git grep exits 1 for no match and above 1 for a failure; outside a work tree it could not look, so it refuses
# to run instead of reporting a clean tree.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "check-names: not inside a git work tree, so tracked files can't be checked" >&2
  exit 2
fi

pattern='paztport[_]claude|super[p]owers|docs/(spec[s]|plan[s])/'

if git grep -n -i -E "$pattern" -- .; then
  echo "check-names: a tracked file names the private workspace or a process artefact (see file:line above)" >&2
  exit 1
fi
