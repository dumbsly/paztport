// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { checkDepth, PROTOCOL, quote, sortedNames, utf8Length, writeScalar } from "./jcs.ts";
import { JSON_LIMITS, type JsonValue } from "./json.ts";

/**
 * A file in the one form every implementation writes (spec wire.md, JSON, Files): members in JCS order and strings
 * as JCS escapes them, two spaces of indent per level, one member or element per line, `": "` after a name, `{}` and
 * `[]` for an empty object and array, and a newline at the end. Refuses what writeWire refuses, with the file limit.
 */
export function printFile(value: JsonValue): string {
  const text = print(value, 0) + "\n";
  const length = utf8Length(text);
  if (length > JSON_LIMITS.fileBytes) PROTOCOL.refuse(`${length} bytes, over ${JSON_LIMITS.fileBytes}`);
  return text;
}

function print(value: unknown, depth: number): string {
  const scalar = writeScalar(value, PROTOCOL);
  if (scalar !== undefined) return scalar;
  checkDepth(depth, PROTOCOL);
  const inner = "\n" + "  ".repeat(depth + 1);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const elements = Array.from(value, (element) => inner + print(element, depth + 1));
    return "[" + elements.join(",") + "\n" + "  ".repeat(depth) + "]";
  }
  const obj = value as Record<string, unknown>;
  const names = sortedNames(obj, PROTOCOL);
  if (names.length === 0) return "{}";
  const members = names.map((name) => inner + quote(name, PROTOCOL) + ": " + print(obj[name], depth + 1));
  return "{" + members.join(",") + "\n" + "  ".repeat(depth) + "}";
}
