// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The schema step of reading an object (spec wire.md, JSON, Reading step 4), for a value the reader has read: the
// value is an object, it has exactly the members its section defines, and each is of its type. Each refusal names
// the member the schema defines, never a name or value the input chose.

import type { JsonObject, JsonValue } from "../encoding/json.ts";

function isObject(v: JsonValue): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** `v` as an object; anything else is refused. */
export function object(v: JsonValue): JsonObject {
  if (!isObject(v)) throw new Error("not an object");
  return v;
}

/** Refuses `o` unless it has every member in `required` and none outside it and `optional`. */
export function exactly(o: JsonObject, required: readonly string[], optional: readonly string[] = []): void {
  for (const name of required) {
    if (!Object.hasOwn(o, name)) throw new Error(`no member ${name}`);
  }
  for (const name of Object.keys(o)) {
    if (!required.includes(name) && !optional.includes(name)) throw new Error("a member the object does not define");
  }
}

/** The string member `name`; absent or of another type is refused. */
export function str(o: JsonObject, name: string): string {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (typeof v !== "string") throw new Error(`member ${name} is not a string`);
  return v;
}

/** The integer member `name`, a protocol integer as every number the reader gives is; absent or of another type is refused. */
export function int(o: JsonObject, name: string): number {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (typeof v !== "number") throw new Error(`member ${name} is not an integer`);
  return v;
}

/** The boolean member `name`; absent or of another type is refused. */
export function bool(o: JsonObject, name: string): boolean {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (typeof v !== "boolean") throw new Error(`member ${name} is not a boolean`);
  return v;
}

/** A map by definition, such as a keyring's `services`: an object whose every value is a string. Its names are data, so the caller checks them by its section's rules. */
export function stringMap(v: JsonValue): Readonly<Record<string, string>> {
  const o = object(v);
  const out: Record<string, string> = Object.create(null);
  for (const name of Object.keys(o)) {
    const value = o[name];
    if (typeof value !== "string") throw new Error("a map value that is not a string");
    out[name] = value;
  }
  return out;
}
