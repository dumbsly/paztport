#!/usr/bin/env bash
# Fails if a pre-rename runtime name survives in any tracked non-Markdown file.
# Wire names (X-Path-Chain, X-Path-Proof) are deliberately not matched.
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='PATH_ATTEST|path-attest([^a-z]|$)|path_attest|[Pp]athAttest|(^|[^A-Za-z0-9_])PA_[A-Z_]+'

if git grep -nE "$pattern" -- . ':!*.md' ':!scripts/check-names.sh'; then
  echo "check-names: old runtime names remain (see file:line above)" >&2
  exit 1
fi
