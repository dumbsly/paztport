// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

const JSON_WHITESPACE = new Set([" ", "\t", "\n", "\r"]);

/**
 * The text of a key file without its surrounding space, tab, line feed and carriage return, the whitespace of
 * RFC 8259. Any other character, a byte order mark or a no-break space included, stays in the text.
 */
export function keyFileText(text: string): string {
  let from = 0;
  let to = text.length;
  while (from < to && JSON_WHITESPACE.has(text[from]!)) from++;
  while (to > from && JSON_WHITESPACE.has(text[to - 1]!)) to--;
  return text.slice(from, to);
}
