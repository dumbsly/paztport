#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates THIRD-PARTY.txt. The license plugin lists each Java tree's runtime dependencies: the SDK's,
# and the mesh demo's, which adds docker-java and its dependencies, Spring Boot's loader, and Spring Boot's
# Actuator and Micrometer's Prometheus registry with their dependencies. This merges the two lists, sorted
# by name ignoring case and without duplicates, under one count. The demo resolves the SDK from the local
# Maven repository, so run `mvn install` in poc-sdks/java first.
set -euo pipefail
cd "$(dirname "$0")/../.."

(cd poc-sdks/java && mvn -q license:aggregate-add-third-party)
(cd poc-demos/java-mesh && mvn -q license:aggregate-add-third-party)

# Each entry is "     (licence) ... Name (group:artifact:version - url)": sort on the name, after the licences.
entries="$(grep -h '^     (' poc-sdks/java/target/THIRD-PARTY.txt poc-demos/java-mesh/target/THIRD-PARTY.txt \
  | awk '{ k = $0; while (sub(/^ *\([^)]*\) */, "", k)) {} print tolower(k) "\t" $0 }' \
  | LC_ALL=C sort -u | cut -f2-)"

{
  printf '\nLists of %d third-party dependencies.\n' "$(grep -c '' <<<"$entries")"
  printf '%s\n' "$entries"
} > THIRD-PARTY.txt
echo "third-party: wrote $(grep -c '' <<<"$entries") dependencies to THIRD-PARTY.txt"
