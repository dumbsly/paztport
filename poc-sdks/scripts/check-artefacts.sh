#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Checks that each built jar carries the licence files that make it redistributable as built. Every jar
# carries META-INF/LICENSE, the root Apache-2.0 text, and a META-INF/NOTICE that starts with the root NOTICE.
# A jar that bundles third-party code (jars under BOOT-INF/lib, or classes outside org/paztport) carries
# META-INF/THIRD-PARTY.txt, which lists exactly what it bundles, each entry under one licence and as the root
# THIRD-PARTY.txt has it. Its META-INF/licenses/ holds the text of each non-Apache licence listed, as
# licenses/ has it, and no other. Its NOTICE holds the NOTICE of each component whose classes it holds
# unpacked. A jar that bundles nothing carries neither THIRD-PARTY.txt nor META-INF/licenses/. No jar holds
# JMH, and every entry in the root THIRD-PARTY.txt names one licence.
#
# Usage: check-artefacts.sh [jar ...]. With no jar, it checks every jar the two Java trees build, so build
# both first. Components a jar holds unpacked are read from the local Maven repository.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
m2=""

fail() { # jar, then the gap
  echo "check-artefacts: ${1#"$root"/}: $2"
  failures=$((failures + 1))
}

# text_of <licence> <groupId>: the file in licenses/ holding the licence a component is used under. MIT and the
# Bouncy Castle licence name their copyright holder, so they go by group. Prints nothing for Apache-2.0, whose
# text is META-INF/LICENSE; fails for a licence with no text here.
text_of() {
  case "$1|$2" in
    "Apache-2.0|"*) ;;
    "Bouncy Castle Licence|org.bouncycastle") echo bouncy-castle.txt ;;
    "EPL-2.0|"*) echo epl-2.0.txt ;;
    "MIT|org.slf4j") echo mit-slf4j.txt ;;
    "MIT|org.checkerframework") echo mit-checker-framework.txt ;;
    *) return 1 ;;
  esac
}

# repository_jar <g> <a> <v>: sets comp to that jar in the local Maven repository, which the build resolved.
# -N evaluates the path once, also from a directory that holds a multi-module pom.
repository_jar() {
  [ -n "$m2" ] || m2="$(mvn -q -N org.apache.maven.plugins:maven-help-plugin:3.5.2:evaluate -Dexpression=settings.localRepository \
    -DforceStdout </dev/null)"
  comp="$m2/${1//.//}/$2/$3/$2-$3.jar"
}

# entries <THIRD-PARTY.txt>: one "count<TAB>licence<TAB>group<TAB>artifact<TAB>version<TAB>line" per entry,
# where count is how many licences the entry names. An entry is "     (licence) ... Name (g:a:v - url)".
entries() {
  local line rest count licence
  local licence_re='^\(([^)]*)\) (.*)$' coordinates_re='\(([^:() ]+):([^:() ]+):([^:() ]+) - [^()]*\)$'
  while IFS= read -r line; do
    rest="${line#     }"
    count=0
    licence=""
    while [[ "$rest" =~ $licence_re ]]; do
      [ "$count" -gt 0 ] || licence="${BASH_REMATCH[1]}"
      rest="${BASH_REMATCH[2]}"
      count=$((count + 1))
    done
    if ! [[ "$line" =~ $coordinates_re ]]; then
      printf '%s\t%s\t?\t?\t?\t%s\n' "$count" "$licence" "$line"
      continue
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$count" "$licence" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "$line"
  done < <(grep '^     (' "$1" || true)
}

check_jar() {
  local jar="$1" count licence group artifact version line text nested comp notice
  unzip -Z1 "$jar" | LC_ALL=C sort >"$work/entries"
  : >"$work/notice"

  if ! grep -qx 'META-INF/LICENSE' "$work/entries"; then
    fail "$jar" "no META-INF/LICENSE"
  elif ! unzip -p "$jar" META-INF/LICENSE | cmp -s - "$root/LICENSE"; then
    fail "$jar" "META-INF/LICENSE is not the root LICENSE"
  fi
  if ! grep -qx 'META-INF/NOTICE' "$work/entries"; then
    fail "$jar" "no META-INF/NOTICE"
  else
    unzip -p "$jar" META-INF/NOTICE >"$work/notice"
    if [ ! -s "$work/notice" ]; then
      fail "$jar" "META-INF/NOTICE is empty"
    elif ! head -c "$(($(wc -c <"$root/NOTICE")))" "$work/notice" | cmp -s - "$root/NOTICE"; then
      fail "$jar" "META-INF/NOTICE does not start with the root NOTICE"
    fi
  fi
  if grep -Eq '(^|/)org/openjdk/jmh/|^BOOT-INF/lib/jmh-' "$work/entries"; then
    fail "$jar" "holds JMH"
  fi

  # What the jar bundles: third-party jars nested whole, and classes held unpacked (outside Paztport's own).
  grep -E '^BOOT-INF/lib/[^/]+\.jar$' "$work/entries" | sed 's|^BOOT-INF/lib/||' | grep -v '^paztport-' >"$work/nested" || true
  grep '\.class$' "$work/entries" | grep -Ev '^BOOT-INF/lib/|^(BOOT-INF/classes/|META-INF/versions/[0-9]+/)?org/paztport/' >"$work/loose" || true
  grep -E '^META-INF/licenses/[^/]+$' "$work/entries" | sed 's|^META-INF/licenses/||' >"$work/texts" || true

  if [ ! -s "$work/nested" ] && [ ! -s "$work/loose" ]; then
    grep -qx 'META-INF/THIRD-PARTY.txt' "$work/entries" && fail "$jar" "bundles nothing but carries META-INF/THIRD-PARTY.txt"
    [ -s "$work/texts" ] && fail "$jar" "bundles nothing but carries META-INF/licenses/"
    return 0
  fi
  if ! grep -qx 'META-INF/THIRD-PARTY.txt' "$work/entries"; then
    fail "$jar" "bundles third-party code and has no META-INF/THIRD-PARTY.txt"
    return 0
  fi
  unzip -p "$jar" META-INF/THIRD-PARTY.txt >"$work/third-party"
  entries "$work/third-party" >"$work/listed"
  [ -s "$work/listed" ] || fail "$jar" "META-INF/THIRD-PARTY.txt lists nothing"

  : >"$work/accounted"
  : >"$work/needed"
  while IFS=$'\t' read -r count licence group artifact version line; do
    if [ "$group" = "?" ]; then
      fail "$jar" "THIRD-PARTY.txt has an entry without group:artifact:version: $line"
      continue
    fi
    if [ "$count" -ne 1 ]; then
      fail "$jar" "THIRD-PARTY.txt names $count licences for $group:$artifact:$version"
    else
      grep -qxF -- "$line" "$root/THIRD-PARTY.txt" \
        || fail "$jar" "THIRD-PARTY.txt lists ($licence) $group:$artifact:$version, and the root THIRD-PARTY.txt does not"
      if text="$(text_of "$licence" "$group")"; then
        [ -z "$text" ] || printf '%s\t%s\n' "$text" "($licence) $group:$artifact:$version" >>"$work/needed"
      else
        fail "$jar" "THIRD-PARTY.txt lists $group:$artifact:$version under $licence, a licence this check knows no text for"
      fi
    fi

    if grep -qxF -- "$artifact-$version.jar" "$work/nested"; then
      echo "$artifact-$version.jar" >>"$work/accounted"
      continue
    fi
    repository_jar "$group" "$artifact" "$version"
    if [ ! -f "$comp" ]; then
      fail "$jar" "THIRD-PARTY.txt lists $group:$artifact:$version, which is not in BOOT-INF/lib or the local Maven repository"
      continue
    fi
    unzip -Z1 "$comp" | grep '\.class$' | LC_ALL=C sort >"$work/component" || true
    if [ -z "$(LC_ALL=C comm -12 "$work/loose" "$work/component" | head -n1)" ]; then
      fail "$jar" "THIRD-PARTY.txt lists $group:$artifact:$version, whose classes the jar does not hold"
      continue
    fi
    LC_ALL=C comm -23 "$work/loose" "$work/component" >"$work/rest"
    mv "$work/rest" "$work/loose"
    # Unpacked, the component's own NOTICE is gone, so the jar's NOTICE carries it.
    for notice in $(unzip -Z1 "$comp" | grep -E '^META-INF/NOTICE(\.txt|\.md)?$' || true); do
      [[ "$(cat "$work/notice")" == *"$(unzip -p "$comp" "$notice")"* ]] \
        || fail "$jar" "META-INF/NOTICE lacks the $notice of $group:$artifact:$version, whose classes it holds"
    done
  done <"$work/listed"

  while IFS= read -r nested; do
    grep -qxF -- "$nested" "$work/accounted" || fail "$jar" "bundles BOOT-INF/lib/$nested, which THIRD-PARTY.txt does not list"
  done <"$work/nested"
  if [ -s "$work/loose" ]; then
    fail "$jar" "holds $(grep -c '' "$work/loose") classes that no component in THIRD-PARTY.txt has, such as $(head -n1 "$work/loose")"
  fi

  while IFS=$'\t' read -r text comp; do
    grep -qxF -- "$text" "$work/texts" || fail "$jar" "has no META-INF/licenses/$text, the licence of $comp"
  done <"$work/needed"
  while IFS= read -r text; do
    if ! cut -f1 "$work/needed" | grep -qxF -- "$text"; then
      fail "$jar" "carries META-INF/licenses/$text, which no THIRD-PARTY.txt entry is used under"
    elif [ ! -f "$root/licenses/$text" ] || ! unzip -p "$jar" "META-INF/licenses/$text" | cmp -s - "$root/licenses/$text"; then
      fail "$jar" "META-INF/licenses/$text is not licenses/$text"
    fi
  done <"$work/texts"
}

if [ $# -gt 0 ]; then
  jars=("$@")
else
  jars=()
  while IFS= read -r jar; do jars+=("$jar"); done < <(
    find "$root/poc-sdks/java" "$root/poc-demos/java-mesh" -type f -path '*/target/*.jar' \
      | grep '/target/[^/]*$' | LC_ALL=C sort)
  if [ ${#jars[@]} -eq 0 ]; then
    echo "check-artefacts: no jars under poc-sdks/java or poc-demos/java-mesh; build both trees first" >&2
    exit 2
  fi
fi

for jar in "${jars[@]}"; do check_jar "$jar"; done

while IFS=$'\t' read -r count licence group artifact version line; do
  if [ "$group" = "?" ]; then
    fail "$root/THIRD-PARTY.txt" "has an entry without group:artifact:version: $line"
  elif [ "$count" -ne 1 ]; then
    fail "$root/THIRD-PARTY.txt" "names $count licences for $group:$artifact:$version"
  fi
done < <(entries "$root/THIRD-PARTY.txt")

jars_checked="${#jars[@]} jar$([ ${#jars[@]} -eq 1 ] || echo s) and THIRD-PARTY.txt"
if [ "$failures" -gt 0 ]; then
  echo "check-artefacts: $failures gap(s) in $jars_checked" >&2
  exit 1
fi
echo "check-artefacts: ok, $jars_checked"
