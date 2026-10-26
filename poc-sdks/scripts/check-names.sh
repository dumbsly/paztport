#!/usr/bin/env bash
# Fails if a pre-rename runtime name survives in any tracked file, Markdown included.
# Wire names (X-Path-Chain, X-Path-Proof) are deliberately not matched, and nor is
# prose such as "path attestation" or "path-attestation".
set -euo pipefail
cd "$(dirname "$0")/../.."

pattern='PATH_ATTEST|path-attest([^a-z]|$)|path_attest|[Pp]athAttest|(^|[^A-Za-z0-9_])PA_[A-Z_]+'

if git grep -nE "$pattern" -- . ':!poc-sdks/scripts/check-names.sh'; then
  echo "check-names: old runtime names remain (see file:line above)" >&2
  exit 1
fi
