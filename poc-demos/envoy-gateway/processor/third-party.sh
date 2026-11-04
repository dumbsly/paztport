#!/usr/bin/env bash
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# Keeps the processor's THIRD-PARTY.txt true, as check-artefacts.sh keeps the jars'. It lists every third-party
# module the processor's binary is built from, one line each as "     (licence) module version", under one licence
# each; std is Go's standard library and runtime, which every Go binary holds, at the version of the image's
# builder. A module may hold code under a licence of its own below its root, such as a package copied in from
# elsewhere with its LICENSE: each such licence (or NOTICE) file, in a directory that holds a package the binary is
# built from or above one, up to the module's root, is a line of its own after the module's, as
# "     (licence) module version path", the path from the module's root; a NOTICE file is listed as (NOTICE).
#
#   third-party.sh check [list]
#       The list (THIRD-PARTY.txt by default) names exactly the modules `go list -deps` reports for
#       ./cmd/processor, built for linux/amd64 and linux/arm64 without cgo, as the image builds it, with std at
#       the Go version of the Dockerfile's builder, and exactly the licence files within them; each line under
#       one licence, which is the licence its file holds. Nothing is built. ./run test runs this.
#   third-party.sh gather <binary> <outDir>
#       In the image build: the modules `go version -m` reports in the binary, and the licence files within the
#       packages `go list -deps` reports, are the ones THIRD-PARTY.txt names. Writes <outDir>/LICENSE (the
#       repository's), <outDir>/NOTICE (the repository's, then each module's NOTICE files), <outDir>/THIRD-PARTY.txt,
#       and under <outDir>/third-party/<module>@<version>/ each module's licence and patent files, and each licence
#       file within it at its path. Fails for a module with no licence file.
#
# std's own licence files below its root are not listed: those in src/vendor/golang.org/x/* are Go's licence, byte
# for byte, which std's line ships, and the script checks that they are. The one other, crypto/internal/boring/
# LICENSE, says the Go code beside it is under Go's licence and its own terms cover only the BoringSSL object a
# GOEXPERIMENT=boringcrypto build links in; the script checks that the binary is built without cgo or that
# experiment, which cannot link it. Any other licence file in std fails.
#
# The repository's own Go SDK, which the module replaces with its directory, is under the repository's LICENSE and
# is not listed.
set -euo pipefail
# Loops read from files in $work, never from a process substitution, which macOS's bash 3.2 can hang on when it
# runs many in a row.
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
own="github.com/dumbsly/paztport/"
boring="crypto/internal/boring/LICENSE"
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

# is_notice <path>: whether the file is a NOTICE file rather than a licence.
is_notice() {
  case "${1##*/}" in [Nn][Oo][Tt][Ii][Cc][Ee]*) return 0 ;; esac
  return 1
}

# licence_files <dir> [notices]: the licence files in dir itself, and its NOTICE files too when asked, one a line.
licence_files() {
  if [ "${2:-}" = notices ]; then
    find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \)
  else
    find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \)
  fi | LC_ALL=C sort
}

# module_licence <module> <dir>: the one licence the module's root licence files hold; otherwise it prints the gap
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

# go_licence: Go's own LICENSE, which std ships. Homebrew keeps it beside GOROOT rather than in it.
go_licence() {
  local root
  root="$(go env GOROOT)"
  if [ -f "$root/LICENSE" ]; then echo "$root/LICENSE"; elif [ -f "$root/../LICENSE" ]; then echo "$root/../LICENSE"; fi
}

# entries <list>: one "licence<TAB>module<TAB>version<TAB>path" per line, path empty for a module's own line,
# checking each line's form and licence, and the count line.
entries() {
  local line licence path count=0 std=0 n entry_re='^     \(([^()]*)\) ([^ ()]+) ([^ ()]+)( ([^ ()]+))?$'
  while IFS= read -r line; do
    case "$line" in
      "     ("*)
        if ! [[ "$line" =~ $entry_re ]]; then
          fail "a line is not '     (licence) module version [path]': $line"
          continue
        fi
        licence="${BASH_REMATCH[1]}"
        path="${BASH_REMATCH[5]}"
        case "$licence" in
          Apache-2.0 | MIT | ISC | BSD-2-Clause | BSD-3-Clause)
            [ -z "$path" ] || ! is_notice "$path" || fail "$line: a NOTICE file is listed as (NOTICE)" ;;
          NOTICE) [ -n "$path" ] && is_notice "$path" || fail "$line: only a NOTICE file within a module is (NOTICE)" ;;
          *) fail "${BASH_REMATCH[2]} ${BASH_REMATCH[3]} $path is not under one licence this script knows: ($licence)" ;;
        esac
        if [ -z "$path" ]; then
          if [ "${BASH_REMATCH[2]}" = std ]; then std=$((std + 1)); else count=$((count + 1)); fi
        fi
        printf '%s\t%s\t%s\t%s\n' "$licence" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "$path"
        ;;
    esac
  done <"$1"
  n="$(sed -n "s/^The processor is built from \([0-9][0-9]*\) third-party modules plus Go's standard library.*/\1/p" "$1")"
  [ "$n" = "$count" ] || fail "the list says ${n:-no number of} modules and names $count, besides std"
  [ "$std" -eq 1 ] || fail "the list names std $std times, not once"
}

# compare <want> <got> <source> <what>: fails for each line one has and the other does not.
compare() {
  local line
  LC_ALL=C comm -13 "$1" "$2" >"$work/unlisted"
  LC_ALL=C comm -23 "$1" "$2" >"$work/unfound"
  while IFS= read -r line; do fail "$3 has the $4 $line, which the list does not name"; done <"$work/unlisted"
  while IFS= read -r line; do fail "the list names the $4 $line, which $3 does not have"; done <"$work/unfound"
}

# builder_go: the Go version of the Dockerfile's builder image, such as go1.27.3.
builder_go() {
  [ -f "$here/Dockerfile" ] || return 0
  sed -n 's/^FROM golang:\([0-9][0-9.]*\)[-@].*/go\1/p' "$here/Dockerfile" | head -n1
}

# discover <prefix> <go>: reads the `go list -deps` lines in <prefix>.pkgs and writes <prefix>.modules (one
# "module version" each, std as "std <go>") and <prefix>.nested (one "module version path<TAB>file" for each
# licence or NOTICE file below a module's root, in a directory that holds a compiled package or above one). It
# checks std's own such files as the header says.
discover() {
  local prefix="$1" go="$2" pdir a b c d e module version root x f rel gl stdroot
  : >"$prefix.modules"
  : >"$prefix.nested"
  stdroot="$(go env GOROOT)/src"
  gl="$(go_licence)"
  [ -n "$gl" ] || fail "no LICENSE in or beside GOROOT, $(go env GOROOT)"
  while IFS='|' read -r pdir a b c d e; do
    case "$a" in
      main) continue ;;
      std) module=std version="$go" root="$stdroot" ;;
      *)
        if [ -n "$d" ] && [ -z "$e" ]; then
          # A replacement by a directory: the repository's own code, and only the Go SDK may be one.
          [ "${a#"$own"}" != "$a" ] || fail "a module outside the repository is replaced by a directory: $a"
          continue
        fi
        if [ -n "$d" ]; then module="$d" version="$e"; else module="$a" version="$b"; fi
        root="$c"
        ;;
    esac
    echo "$module $version" >>"$prefix.modules"
    if [ "$pdir" != "$root" ] && [ "${pdir#"$root"/}" = "$pdir" ]; then
      fail "the package directory $pdir is not under its module's root, $root"
      continue
    fi
    x="$pdir"
    while [ "$x" != "$root" ] && [ "${x#"$root"/}" != "$x" ]; do
      licence_files "$x" notices >"$work/found"
      while IFS= read -r f; do
        printf '%s %s %s\t%s\n' "$module" "$version" "${f#"$root"/}" "$f" >>"$prefix.nested"
      done <"$work/found"
      x="$(dirname "$x")"
    done
  done <"$prefix.pkgs"
  LC_ALL=C sort -u -o "$prefix.modules" "$prefix.modules"
  LC_ALL=C sort -u -o "$prefix.nested" "$prefix.nested"

  # std's own: Go's licence, or the BoringCrypto note, which only a boringcrypto build makes a licence of.
  grep "^std " "$prefix.nested" >"$work/std-nested" || true
  while IFS=$'\t' read -r rel f; do
    rel="${rel#std "$go" }"
    if [ -n "$gl" ] && cmp -s "$f" "$gl"; then
      continue
    elif [ "$rel" = "$boring" ]; then
      continue
    fi
    fail "std holds $rel, which is not Go's licence"
  done <"$work/std-nested"
  grep -v "^std " "$prefix.nested" >"$prefix.nested-modules" || true
  cut -f1 "$prefix.nested-modules" >"$prefix.nested-names"
}

# packages <prefix> [env...]: `go list -deps` of ./cmd/processor under env, one "dir|..." a package, into
# <prefix>.pkgs: "dir|std", "dir|main", or "dir|module|version|moduleDir[|replacement|replacementVersion]".
packages() {
  local prefix="$1"
  shift
  local format='{{.Dir}}|{{if .Standard}}std{{else}}{{with .Module}}{{if .Main}}main{{else}}'
  format="$format"'{{.Path}}|{{.Version}}|{{.Dir}}{{with .Replace}}|{{.Path}}|{{.Version}}{{end}}{{end}}{{end}}{{end}}'
  (cd "$here" && env "$@" go list -deps -f "$format" ./cmd/processor) >"$prefix.pkgs"
}

# listed <entries>: writes $work/listed ("module version") and $work/listed-nested ("module version path").
listed() {
  awk -F '\t' '$4 == "" { print $2 " " $3 }' "$1" | LC_ALL=C sort >"$work/listed"
  awk -F '\t' '$4 != "" { print $2 " " $3 " " $4 }' "$1" | LC_ALL=C sort >"$work/listed-nested"
  [ -z "$(uniq -d "$work/listed")" ] || fail "the list names a module twice"
  [ -z "$(uniq -d "$work/listed-nested")" ] || fail "the list names a licence file twice"
}

# summary: what the list names, in words.
summary() {
  echo "$(($(grep -c '' "$work/listed") - 1)) modules plus std, and $(grep -c '' "$work/listed-nested") licence file(s) within them"
}

# nested_file <prefix> <module> <version> <path>: the file a listed licence file is, from discover's output.
nested_file() {
  awk -F '\t' -v k="$2 $3 $4" '$1 == k { print $2; exit }' "$1.nested-modules"
}

# check_nested_licence <file> <licence> <name>: the file holds the licence listed, or is a NOTICE listed so.
check_nested_licence() {
  local found
  if [ "$2" = NOTICE ]; then return 0; fi
  found="$(licence_of "$1")"
  [ "$found" = "$2" ] || fail "the list names $3 under $2, and the file holds ${found:-no one licence this script knows}"
}

cmd_check() {
  local list="${1:-$here/THIRD-PARTY.txt}" arch licence module version path dir found go gl
  [ -f "$list" ] || { echo "third-party: no ${list#"$repo"/}" >&2; exit 1; }
  entries "$list" >"$work/entries"
  listed "$work/entries"

  go="$(builder_go)"
  [ -n "$go" ] || fail "the Dockerfile names no golang:<version> builder"
  case "$(CGO_ENABLED=0 go env GOEXPERIMENT)" in *boringcrypto*) fail "GOEXPERIMENT holds boringcrypto" ;; esac
  for arch in amd64 arm64; do
    packages "$work/$arch" CGO_ENABLED=0 GOOS=linux GOARCH="$arch"
    discover "$work/$arch" "$go"
    compare "$work/listed" "$work/$arch.modules" "go list -deps for linux/$arch" module
    compare "$work/listed-nested" "$work/$arch.nested-names" "go list -deps for linux/$arch" "licence file"
  done

  while IFS=$'\t' read -r licence module version path; do
    if [ -n "$path" ]; then
      dir="$(nested_file "$work/amd64" "$module" "$version" "$path")"
      [ -z "$dir" ] || check_nested_licence "$dir" "$licence" "$module $version $path"
      continue
    fi
    if [ "$module" = std ]; then
      gl="$(go_licence)"
      if [ "$licence" != BSD-3-Clause ]; then
        fail "std is under BSD-3-Clause, and the list names $licence"
      elif [ -n "$gl" ] && [ "$(licence_of "$gl")" != BSD-3-Clause ]; then
        fail "Go's LICENSE, $gl, is not BSD-3-Clause"
      fi
      continue
    fi
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
  echo "third-party: ok, $(summary), in ${list#"$repo"/}"
}

cmd_gather() {
  local binary="$1" out="$2" licence module version path dir dest f found go
  [ -f "$here/THIRD-PARTY.txt" ] || { echo "third-party: no THIRD-PARTY.txt" >&2; exit 1; }
  entries "$here/THIRD-PARTY.txt" >"$work/entries"
  listed "$work/entries"

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
  compare "$work/listed" "$work/modules" "$binary" module
  # crypto/internal/boring's own terms apply only to a cgo build with the boringcrypto experiment.
  grep -q '^[[:space:]]*build[[:space:]]*CGO_ENABLED=0$' "$work/buildinfo" || fail "$binary is not built with CGO_ENABLED=0"
  ! grep -q 'GOEXPERIMENT=.*boringcrypto' "$work/buildinfo" || fail "$binary is built with boringcrypto"

  # The licence files within the modules, from the packages this build compiles.
  packages "$work/build" CGO_ENABLED=0
  discover "$work/build" "$go"
  compare "$work/listed" "$work/build.modules" "go list -deps" module
  compare "$work/listed-nested" "$work/build.nested-names" "go list -deps" "licence file"
  [ "$failures" -eq 0 ] || { echo "third-party: $failures gap(s); nothing gathered" >&2; exit 1; }

  mkdir -p "$out/third-party"
  cp "$repo/LICENSE" "$out/LICENSE"
  cp "$repo/NOTICE" "$out/NOTICE"
  cp "$here/THIRD-PARTY.txt" "$out/THIRD-PARTY.txt"
  while IFS=$'\t' read -r licence module version path; do
    dest="$out/third-party/$module@$version"
    if [ -n "$path" ]; then
      f="$(nested_file "$work/build" "$module" "$version" "$path")"
      check_nested_licence "$f" "$licence" "$module $version $path"
      mkdir -p "$dest/$(dirname "$path")"
      cp "$f" "$dest/$path"
      if [ "$licence" = NOTICE ]; then
        printf '\n%s %s, %s:\n\n' "$module" "$version" "$path" >>"$out/NOTICE"
        cat "$f" >>"$out/NOTICE"
      fi
      continue
    fi
    if [ "$module" = std ]; then
      dir="$(go env GOROOT)"
    else
      dir="$(cd "$here" && go list -m -f '{{.Dir}}' "$module@$version")"
    fi
    mkdir -p "$dest"
    if found="$(module_licence "$module" "$dir")"; then
      [ "$found" = "$licence" ] || fail "THIRD-PARTY.txt names $module $version under $licence, and its licence file holds $found"
    else
      fail "$found"
      continue
    fi
    licence_files "$dir" >"$work/found"
    while IFS= read -r f; do cp "$f" "$dest/"; done <"$work/found"
    [ ! -f "$dir/PATENTS" ] || cp "$dir/PATENTS" "$dest/"
    # The module's code is compiled into the binary, so its NOTICE travels in the image's NOTICE.
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
  echo "third-party: gathered the licences of $(summary), into $out"
}

case "${1:-}" in
  check) shift; [ $# -le 1 ] || { echo "usage: third-party.sh check [list]" >&2; exit 2; }; cmd_check "$@" ;;
  gather) shift; [ $# -eq 2 ] || { echo "usage: third-party.sh gather <binary> <outDir>" >&2; exit 2; }; cmd_gather "$@" ;;
  *) echo "usage: third-party.sh check [list] | gather <binary> <outDir>" >&2; exit 2 ;;
esac
