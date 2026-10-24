// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

function str(s: string): string {
  if (/\p{Surrogate}/u.test(s)) throw new TypeError("jcs: lone surrogate");
  return JSON.stringify(s);
}

/** RFC 8785 JSON Canonicalization Scheme. Throws on values that are not JSON. */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return str(value);
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("jcs: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + Array.from(value, canonicalize).join(",") + "]";
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError("jcs: non-plain object");
      }
      const obj = value as Record<string, unknown>;
      return (
        "{" +
        Object.keys(obj)
          .sort()
          .map((k) => str(k) + ":" + canonicalize(obj[k]))
          .join(",") +
        "}"
      );
    }
    default:
      throw new TypeError(`jcs: unsupported type ${typeof value}`);
  }
}
