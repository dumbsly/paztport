// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { sha256 } from "../crypto/crypto.ts";
import { canonicalize, writeWire } from "../encoding/jcs.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { array, exactly, object, str } from "../internal/fields.ts";

export type InfluenceClass = "third-party" | "private" | "public" | "local-untrusted";
export type InfluenceEntry = { cls: InfluenceClass; src: string; h: string; cid?: string; owner?: string };

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function cmpOptional(a: string | undefined, b: string | undefined): number {
  return a === undefined ? (b === undefined ? 0 : -1) : b === undefined ? 1 : cmp(a, b);
}

/** Sorts by h, cls, src, cid, then owner (absent first), and removes all exact duplicates. */
export function normalizeInfluence(entries: InfluenceEntry[]): InfluenceEntry[] {
  const sorted = entries
    .map((e): InfluenceEntry => {
      const base: InfluenceEntry = { cls: e.cls, src: e.src, h: e.h };
      if (e.cid !== undefined) base.cid = e.cid;
      if (e.owner !== undefined) base.owner = e.owner;
      return base;
    })
    .sort((a, b) => cmp(a.h, b.h) || cmp(a.cls, b.cls) || cmp(a.src, b.src) || cmpOptional(a.cid, b.cid) || cmpOptional(a.owner, b.owner));
  const seen = new Set<string>();
  return sorted.filter((e) => {
    const k = canonicalize(e);
    if (seen.has(k)) {
      return false;
    }
    seen.add(k);
    return true;
  });
}

const CLASSES: readonly string[] = ["third-party", "private", "public", "local-untrusted"];

/**
 * The entries of an influence list the reader has read, each with exactly an entry's members: a known `cls`, `src`
 * and `h`, and an optional `cid` and non-empty `owner`, all strings. Throws an Error naming what it refuses.
 * Internal: index.ts exports readInfluence.
 */
export function influenceOf(value: JsonValue): InfluenceEntry[] {
  return array(value).map((item) => {
    const o = object(item);
    exactly(o, ["cls", "src", "h"], ["cid", "owner"]);
    const cls = str(o, "cls");
    if (!CLASSES.includes(cls)) {
      throw new Error("member cls is not an influence class");
    }
    const entry: InfluenceEntry = { cls: cls as InfluenceClass, src: str(o, "src"), h: str(o, "h") };
    if (Object.hasOwn(o, "cid")) {
      entry.cid = str(o, "cid");
    }
    if (Object.hasOwn(o, "owner")) {
      entry.owner = str(o, "owner");
      if (entry.owner === "") {
        throw new Error("member owner is empty");
      }
    }
    return entry;
  });
}

/** Reads an influence list from its token: MalformedJson for bytes that do not read, an Error naming the member for an entry the schema refuses. */
export function readInfluence(token: string): InfluenceEntry[] {
  return influenceOf(readToken(token));
}

/** Empty string for no influence, otherwise b64url(SHA-256(JCS(normalized entries))). */
export function commitInfluence(entries: InfluenceEntry[]): string {
  if (entries.length === 0) {
    return "";
  }
  return encode(sha256(writeWire(normalizeInfluence(entries) as JsonValue[])));
}

export function influenceClasses(entries: InfluenceEntry[]): Set<InfluenceClass> {
  return new Set(entries.map((e) => e.cls));
}
