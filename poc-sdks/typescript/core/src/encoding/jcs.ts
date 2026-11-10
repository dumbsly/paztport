// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// JCS (RFC 8785) under two sets of rules: canonicalize writes hashed content, and writeWire and writeToken write
// Paztport's own objects, refusing whatever a reader refuses (spec wire.md, JSON). index.ts exports those three;
// the rest is shared with json.ts and json-file.ts. What the readers and writers agree on is in json-rules.ts.

import { encode } from "./b64url.ts";
import { JSON_LIMITS, MalformedJson, noncharacter } from "./json-rules.ts";
import type { JsonValue } from "./json.ts";

/** What a writer refuses, and how it says so. */
export type Rules = { readonly protocol: boolean; readonly refuse: (why: string) => never };

const HASHED: Rules = {
  protocol: false,
  refuse: (why) => {
    throw new TypeError(`jcs: ${why}`);
  },
};

/** The writer's rules for Paztport's own objects: it refuses what a reader refuses, with MalformedJson. */
export const PROTOCOL: Rules = {
  protocol: true,
  refuse: (why) => {
    throw new MalformedJson("write", why);
  },
};

const ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

/** A string as RFC 8785 §3.2.2.2 writes it: seven short escapes, \u00xx for other controls, the rest as itself. */
export function quote(s: string, rules: Rules): string {
  let out = '"';
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdfff) {
      const next = s.charCodeAt(i + 1);
      if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) rules.refuse("a lone surrogate");
      const cp = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
      if (rules.protocol && noncharacter(cp)) rules.refuse(`the noncharacter U+${cp.toString(16).toUpperCase()}`);
      i++;
    } else if (unit < 0x20 || unit === 0x22 || unit === 0x5c) {
      out += s.slice(from, i) + (ESCAPES[unit] ?? "\\u00" + unit.toString(16).padStart(2, "0"));
      from = i + 1;
    } else if (rules.protocol && noncharacter(unit)) {
      rules.refuse(`the noncharacter U+${unit.toString(16).toUpperCase()}`);
    }
  }
  return out + s.slice(from) + '"';
}

/** An object's names in RFC 8785 §3.2.3 order: JavaScript compares strings by their UTF-16 code units. */
export function sortedNames(value: object, rules: Rules): string[] {
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) rules.refuse("non-plain object");
  return Object.keys(value).sort();
}

/** A literal, number or string as JCS writes it, or undefined for an array or object, whose layout is the caller's. */
export function writeScalar(value: unknown, rules: Rules): string | undefined {
  switch (typeof value) {
    case "object":
      return value === null ? "null" : undefined;
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return quote(value, rules);
    case "number":
      if (rules.protocol) {
        // -0 too, which would read back as 0.
        if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
          rules.refuse(`${String(value)} is not a protocol integer`);
        }
      } else if (!Number.isFinite(value)) {
        rules.refuse("non-finite number");
      }
      // ECMAScript's Number-to-String, the shortest form RFC 8785 §3.2.2.3 names; -0 is "0".
      return String(value);
    default:
      return rules.refuse(`unsupported type ${typeof value}`);
  }
}

/** The protocol's depth check, before an array or object `depth` levels down is written. */
export function checkDepth(depth: number, rules: Rules): void {
  if (rules.protocol && depth === JSON_LIMITS.depth) {
    rules.refuse(`an array or object nested deeper than ${JSON_LIMITS.depth} levels`);
  }
}

function write(value: unknown, rules: Rules, depth: number): string {
  const scalar = writeScalar(value, rules);
  if (scalar !== undefined) return scalar;
  checkDepth(depth, rules);
  if (Array.isArray(value)) {
    let out = "[";
    for (let i = 0; i < value.length; i++) out += (i === 0 ? "" : ",") + write(value[i], rules, depth + 1);
    return out + "]";
  }
  const obj = value as Record<string, unknown>;
  const members = sortedNames(obj, rules).map((name) => quote(name, rules) + ":" + write(obj[name], rules, depth + 1));
  return "{" + members.join(",") + "}";
}

/** RFC 8785 JSON Canonicalization Scheme, for hashed content. Throws on values that are not JSON. */
export function canonicalize(value: unknown): string {
  return write(value, HASHED, 0);
}

/** The UTF-8 length of text that holds no lone surrogate. */
export function utf8Length(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    // A surrogate pair is four bytes: two for each of its units.
    n += unit < 0x80 ? 1 : unit < 0x800 || (unit >= 0xd800 && unit <= 0xdfff) ? 2 : 3;
  }
  return n;
}

/** The canonical bytes of a Paztport object, refused as a reader would refuse them, over the wire limit included. */
export function writeWire(value: JsonValue): Uint8Array {
  const text = write(value, PROTOCOL, 0);
  const length = utf8Length(text);
  if (length > JSON_LIMITS.wireBytes) PROTOCOL.refuse(`${length} bytes, over ${JSON_LIMITS.wireBytes}`);
  const bytes = new Uint8Array(length);
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    let cp = text.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) cp = 0x10000 + ((cp - 0xd800) << 10) + (text.charCodeAt(++i) - 0xdc00);
    if (cp < 0x80) {
      bytes[n++] = cp;
    } else if (cp < 0x800) {
      bytes[n++] = 0xc0 | (cp >> 6);
      bytes[n++] = 0x80 | (cp & 0x3f);
    } else if (cp < 0x10000) {
      bytes[n++] = 0xe0 | (cp >> 12);
      bytes[n++] = 0x80 | ((cp >> 6) & 0x3f);
      bytes[n++] = 0x80 | (cp & 0x3f);
    } else {
      bytes[n++] = 0xf0 | (cp >> 18);
      bytes[n++] = 0x80 | ((cp >> 12) & 0x3f);
      bytes[n++] = 0x80 | ((cp >> 6) & 0x3f);
      bytes[n++] = 0x80 | (cp & 0x3f);
    }
  }
  return bytes;
}

/** writeWire's bytes as a base64url token. */
export function writeToken(value: JsonValue): string {
  return encode(writeWire(value));
}
