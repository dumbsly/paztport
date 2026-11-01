#!/usr/bin/env bash
# Fails if a tracked file names the private workspace or the process artefacts (its folder, the tool that
# drives the work, the design-document folders). The repo never names them. Case does not matter.
# Each name is written with one letter in a bracket, so this file does not contain the names it looks for
# and needs no exclusion of its own.
set -euo pipefail
cd "$(dirname "$0")/../.."

pattern='paztport[_]claude|super[p]owers|docs/(spec[s]|plan[s])/'

if git grep -n -i -E "$pattern" -- .; then
  echo "check-names: a tracked file names the private workspace or a process artefact (see file:line above)" >&2
  exit 1
fi
