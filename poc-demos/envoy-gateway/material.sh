#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Makes the keys and the signed policy this proof of concept runs on, with the Java tools, into out/ (not committed:
# it holds private keys). In a real deployment CI does this, not the cluster; this stands in for it.
#
#   ./run envoy-gateway          builds the tool jars, then runs this
#   material.sh [--fresh] [outDir]
#
# outDir defaults to out/ beside this script. It must not exist already: the keys it holds are the ones the cluster
# was set up with, so they are never replaced by accident. --fresh deletes it first and makes everything again.
# PAZTPORT_POLICY_DAYS (default 7) says how long the keyring and the policy root vouch for the keys.
# PAZTPORT_JAVA names the java to run the jars with (./run passes the JDK Maven uses); otherwise java on the PATH.
#
# Writes <outDir>/keys (keygen: edge, orders and payment, a server certificate for the processor, a client
# certificate for the checks) and <outDir>/policy (policy-tool: the signed root and the proof bundles).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sdk="$here/../../poc-sdks/java/tools"
java="${PAZTPORT_JAVA:-java}"

fresh=false
if [ "${1:-}" = --fresh ]; then fresh=true; shift; fi
[ $# -le 1 ] || { echo "usage: material.sh [--fresh] [outDir]" >&2; exit 2; }
out="${1:-$here/out}"

for jar in "$sdk/keygen/target/keygen.jar" "$sdk/policy-tool/target/policy-tool.jar"; do
  [ -f "$jar" ] || { echo "missing: $jar (run mvn -q install -DskipTests in poc-sdks/java)" >&2; exit 1; }
done

if [ -e "$out" ]; then
  if [ "$fresh" = true ]; then
    rm -rf "$out"
  else
    echo "$out exists; the cluster's keys are in it. Use --fresh to make new ones." >&2
    exit 1
  fi
fi

"$java" -jar "$sdk/keygen/target/keygen.jar" "$out/keys" edge orders payment --tls-only paztport-processor operator
"$java" -jar "$sdk/policy-tool/target/policy-tool.jar" "$here/paths.yaml" "$out/keys" "$out/policy"
