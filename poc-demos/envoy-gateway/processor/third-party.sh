#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Keeps the processor's THIRD-PARTY.txt true, as check-artefacts.sh keeps the jars': it lists, one line each,
# every third-party module the processor's binary is built from, as "     (licence) module version", under one
# licence each. std is Go's standard library and runtime, which every Go binary holds, at the version of the
# image's builder.
#
#   third-party.sh check [list]
#       The list (THIRD-PARTY.txt by default) names exactly the modules `go list -deps` reports for
#       ./cmd/processor, built for linux/amd64 and linux/arm64 without cgo, as the image builds it, and std
#       at the Go version of the Dockerfile's builder; each under one licence, which is the licence its
#       licence file holds. Nothing is built. ./run test runs this.
#   third-party.sh gather <binary> <outDir>
#       In the image build: the modules `go version -m` reports in the binary are the ones THIRD-PARTY.txt
#       names. Writes <outDir>/LICENSE (the repository's), <outDir>/NOTICE (the repository's, then each
#       module's NOTICE), <outDir>/THIRD-PARTY.txt, and each module's licence and patent files under
#       <outDir>/third-party/<module>@<version>/. Fails for a module with no licence file.
#
# The repository's own Go SDK, which the module replaces with its directory, is under the repository's
# LICENSE and is not listed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
own="github.com/dumbsly/paztport/"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "third-party: $1" >&2
  failures=$((failures + 1))
}

# licence_of <file>: the one licence the file's text is, or nothing when it is none or more than one this
# script knows. Line breaks and runs of space are folded first, so wrapping does not matter.
licence_of() {
  local text found=()
  text="$(tr -s '[:space:]' ' ' <"$1")"
  case "$text" in *"Apache License"*"Version 2.0"*) found+=(Apache-2.0) ;; esac
  case "$text" in *"Permission is hereby granted, free of charge"*) found+=(MIT) ;; esac
  case "$text" in *"Permission to use, copy, modify, and/or distribute this software for any purpose"*) found+=(ISC) ;; esac
  case "$text" in
    *"Redistribution and use in source and binary forms"*"Neither the name"*) found+=(BSD-3-Clause) ;;
    *"Redistribution and use in source and binary forms"*) found+=(BSD-2-Clause) ;;
  esac
  [ ${#found[@]} -ne 1 ] || echo "${found[0]}"
}

# licence_files <dir>: the licence files at a module's root, one a line.
licence_files() {
  find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \) | LC_ALL=C sort
}

# module_licence <module> <dir>: the one licence the module's licence files hold; otherwise it prints the gap
# and returns 1, for the caller to fail with (it runs in a subshell, which cannot count failures).
module_licence() {
  local files f l licences=""
  files="$(licence_files "$2")"
  if [ -z "$files" ]; then
    echo "$1 has no licence file in $2"
    return 1
  fi
  while IFS= read -r f; do
    l="$(licence_of "$f")"
    if [ -z "$l" ]; then
      echo "$1: ${f##*/} is not one licence this script knows"
      return 1
    fi
    case " $licences " in *" $l "*) ;; *) licences="${licences:+$licences }$l" ;; esac
  done <<<"$files"
  case "$licences" in
    *" "*) echo "$1 holds more than one licence: $licences"; return 1 ;;
  esac
  echo "$licences"
}

# entries <list>: one "licence<TAB>module<TAB>version" per entry, checking that each names one licence this
# script knows and that the count line is right.
entries() {
  local line rest licence count=0 n entry_re='^     \(([^()]*)\) ([^ ()]+) ([^ ()]+)$'
  while IFS= read -r line; do
    case "$line" in
      "     ("*)
        count=$((count + 1))
        if ! [[ "$line" =~ $entry_re ]]; then
          fail "an entry is not '     (licence) module version': $line"
          continue
        fi
        licence="${BASH_REMATCH[1]}"
        case "$licence" in
          Apache-2.0 | MIT | ISC | BSD-2-Clause | BSD-3-Clause) ;;
          *) fail "${BASH_REMATCH[2]} ${BASH_REMATCH[3]} is not under one licence this script knows: ($licence)" ;;
        esac
        printf '%s\t%s\t%s\n' "$licence" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
        ;;
    esac
  done <"$1"
  n="$(sed -n 's/^The processor is built from \([0-9][0-9]*\) third-party modules.*/\1/p' "$1")"
  [ "$n" = "$count" ] || fail "the list says ${n:-no number of} modules and holds $count"
}

# compare <want> <got> <source>: fails for each module one has and the other does not.
compare() {
  local line
  while IFS= read -r line; do fail "$3 has $line, which the list does not name"; done < <(LC_ALL=C comm -13 "$1" "$2")
  while IFS= read -r line; do fail "the list names $line, which $3 does not have"; done < <(LC_ALL=C comm -23 "$1" "$2")
}

# builder_go: the Go version of the Dockerfile's builder image, such as go1.27.3.
builder_go() {
  [ -f "$here/Dockerfile" ] || return 0
  sed -n 's/^FROM golang:\([0-9][0-9.]*\)[-@].*/go\1/p' "$here/Dockerfile" | head -n1
}

cmd_check() {
  local list="${1:-$here/THIRD-PARTY.txt}" arch licence module version dir found go
  [ -f "$list" ] || { echo "third-party: no ${list#"$repo"/}" >&2; exit 1; }
  entries "$list" >"$work/entries"
  cut -f2,3 "$work/entries" | tr '\t' ' ' | LC_ALL=C sort >"$work/listed"
  [ "$(uniq -d "$work/listed")" = "" ] || fail "the list names a module twice"

  go="$(builder_go)"
  [ -n "$go" ] || fail "the Dockerfile names no golang:<version> builder"
  for arch in amd64 arm64; do
    (cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go list -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{with .Replace}} {{.Path}} {{.Version}}{{end}}{{end}}{{end}}' \
      ./cmd/processor) >"$work/deps-$arch"
    {
      echo "std $go"
      # A local replacement is the repository's own code, and only the Go SDK may be one.
      awk -v own="$own" 'NF == 2 { print } NF == 3 && index($1, own) != 1 { print "local:" $1 } NF == 4 { print $3, $4 }' \
        "$work/deps-$arch"
    } | LC_ALL=C sort -u >"$work/modules-$arch"
    if grep -q '^local:' "$work/modules-$arch"; then
      fail "a module outside the repository is replaced by a directory: $(grep '^local:' "$work/modules-$arch" | head -n1)"
    fi
    compare "$work/listed" "$work/modules-$arch" "go list -deps for linux/$arch"
  done

  while IFS=$'\t' read -r licence module version; do
    [ "$module" != std ] || { [ "$licence" = BSD-3-Clause ] || fail "std is under BSD-3-Clause, not $licence"; continue; }
    dir="$(cd "$here" && go list -m -f '{{.Dir}}' "$module@$version" 2>/dev/null || true)"
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
      fail "$module $version is not in the module cache (go mod download)"
      continue
    fi
    if found="$(module_licence "$module" "$dir")"; then
      [ "$found" = "$licence" ] || fail "the list names $module $version under $licence, and its licence file holds $found"
    else
      fail "$found"
    fi
  done <"$work/entries"

  if [ "$failures" -gt 0 ]; then
    echo "third-party: $failures gap(s) in ${list#"$repo"/}" >&2
    exit 1
  fi
  echo "third-party: ok, $(grep -c '' "$work/listed") modules in ${list#"$repo"/}"
}

cmd_gather() {
  local binary="$1" out="$2" licence module version dir dest f found go
  [ -f "$here/THIRD-PARTY.txt" ] || { echo "third-party: no THIRD-PARTY.txt" >&2; exit 1; }
  entries "$here/THIRD-PARTY.txt" >"$work/entries"
  cut -f2,3 "$work/entries" | tr '\t' ' ' | LC_ALL=C sort >"$work/listed"

  go version -m "$binary" >"$work/buildinfo"
  go="$(sed -n '1s/^[^:]*: \(go[0-9][0-9.]*\)$/\1/p' "$work/buildinfo")"
  [ -n "$go" ] || fail "$binary holds no Go version"
  {
    echo "std $go"
    # "dep <module> <version> [sum]", each followed by "=> <replacement> <version> [sum]" when replaced; a
    # replacement by a directory names its path, which starts with . or /, and the version (devel).
    awk -v own="$own" '
      $1 == "dep" { if (pending != "") print pending; pending = $2 " " $3; path = $2; next }
      $1 == "=>" { if ($2 !~ /^[.\/]/) { pending = $2 " " $3 } else if (index(path, own) == 1) { pending = "" }
                   else { pending = "local:" path }; next }
      END { if (pending != "") print pending }' "$work/buildinfo"
  } | LC_ALL=C sort -u >"$work/modules"
  if grep -q '^local:' "$work/modules"; then
    fail "a module outside the repository is replaced by a directory: $(grep '^local:' "$work/modules" | head -n1)"
  fi
  compare "$work/listed" "$work/modules" "$binary"
  [ "$failures" -eq 0 ] || { echo "third-party: $failures gap(s); nothing gathered" >&2; exit 1; }

  mkdir -p "$out/third-party"
  cp "$repo/LICENSE" "$out/LICENSE"
  cp "$repo/NOTICE" "$out/NOTICE"
  cp "$here/THIRD-PARTY.txt" "$out/THIRD-PARTY.txt"
  while IFS=$'\t' read -r licence module version; do
    if [ "$module" = std ]; then
      dir="$(go env GOROOT)"
    else
      dir="$(cd "$here" && go list -m -f '{{.Dir}}' "$module@$version")"
    fi
    dest="$out/third-party/$module@$version"
    mkdir -p "$dest"
    if found="$(module_licence "$module" "$dir")"; then
      [ "$found" = "$licence" ] || fail "THIRD-PARTY.txt names $module $version under $licence, and its licence file holds $found"
    else
      fail "$found"
      continue
    fi
    while IFS= read -r f; do cp "$f" "$dest/"; done < <(licence_files "$dir")
    [ ! -f "$dir/PATENTS" ] || cp "$dir/PATENTS" "$dest/"
    # The module's classes are compiled into the binary, so its NOTICE travels in the image's NOTICE.
    for f in "$dir"/NOTICE "$dir"/NOTICE.txt "$dir"/NOTICE.md; do
      [ -f "$f" ] || continue
      printf '\n%s %s, %s:\n\n' "$module" "$version" "${f##*/}" >>"$out/NOTICE"
      cat "$f" >>"$out/NOTICE"
    done
  done <"$work/entries"

  if [ "$failures" -gt 0 ]; then
    echo "third-party: $failures gap(s) gathering the licences of $binary" >&2
    exit 1
  fi
  echo "third-party: gathered the licences of $(grep -c '' "$work/listed") modules into $out"
}

case "${1:-}" in
  check) shift; [ $# -le 1 ] || { echo "usage: third-party.sh check [list]" >&2; exit 2; }; cmd_check "$@" ;;
  gather) shift; [ $# -eq 2 ] || { echo "usage: third-party.sh gather <binary> <outDir>" >&2; exit 2; }; cmd_gather "$@" ;;
  *) echo "usage: third-party.sh check [list] | gather <binary> <outDir>" >&2; exit 2 ;;
esac
