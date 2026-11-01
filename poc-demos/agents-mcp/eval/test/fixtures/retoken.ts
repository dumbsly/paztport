// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only edits of the tokens an evidence record holds: a tamper test reads a token, changes its value and writes it
// back, as an attacker editing the file would.

import { canonicalize, encode, readToken, utf8, type JsonValue } from "@paztport/core";

/**
 * `token` with its value edited: read, changed by `edit`, and written back as the base64url of its JCS text, whether
 * or not the strict writer would write it, so an edit can leave a value no reader reads.
 */
export function retoken(token: string, edit: (v: JsonValue) => JsonValue): string {
  return tokenOf(edit(readToken(token)));
}

/** The base64url of a value's JCS text, whether or not the strict writer would write it. */
export function tokenOf(value: unknown): string {
  return encode(utf8(canonicalize(value)));
}

/** `token` with its value changed in place by `change`: retoken for an edit that mutates rather than returns. */
export function changed(token: string, change: (v: any) => void): string {
  return retoken(token, (v) => {
    change(v);
    return v;
  });
}
