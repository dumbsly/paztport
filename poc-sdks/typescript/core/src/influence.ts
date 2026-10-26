// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "./b64url.ts";
import { sha256, utf8 } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";

export type InfluenceClass = "third-party" | "private" | "public" | "local-untrusted";
export type InfluenceEntry = { cls: InfluenceClass; src: string; h: string; cid?: string };

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Sorts by h, cls, src, then cid (absent first), and removes all exact duplicates. */
export function normalizeInfluence(entries: InfluenceEntry[]): InfluenceEntry[] {
  const sorted = entries
    .map((e): InfluenceEntry => (e.cid === undefined ? { cls: e.cls, src: e.src, h: e.h } : { cls: e.cls, src: e.src, h: e.h, cid: e.cid }))
    .sort(
      (a, b) =>
        cmp(a.h, b.h) ||
        cmp(a.cls, b.cls) ||
        cmp(a.src, b.src) ||
        (a.cid === undefined ? (b.cid === undefined ? 0 : -1) : b.cid === undefined ? 1 : cmp(a.cid, b.cid)),
    );
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
const LONE_SURROGATE = /\p{Surrogate}/u;

/** Throws unless value is an array of well-formed influence entries. */
export function parseInfluence(value: unknown): InfluenceEntry[] {
  if (!Array.isArray(value)) {
    throw new Error("influence must be an array");
  }
  return value.map((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("influence entry must be an object");
    }
    const o = item as Record<string, unknown>;
    if (typeof o.cls !== "string" || !CLASSES.includes(o.cls) || typeof o.src !== "string" || typeof o.h !== "string") {
      throw new Error("malformed influence entry");
    }
    if (o.cid !== undefined && typeof o.cid !== "string") {
      throw new Error("malformed influence cid");
    }
    for (const f of [o.src, o.h, o.cid]) {
      if (typeof f === "string" && LONE_SURROGATE.test(f)) {
        throw new Error("lone surrogate in influence entry");
      }
    }
    const base = { cls: o.cls as InfluenceClass, src: o.src, h: o.h };
    return o.cid === undefined ? base : { ...base, cid: o.cid as string };
  });
}

/** Empty string for no influence, otherwise b64url(SHA-256(JCS(normalized entries))). */
export function commitInfluence(entries: InfluenceEntry[]): string {
  if (entries.length === 0) {
    return "";
  }
  return encode(sha256(utf8(canonicalize(normalizeInfluence(entries)))));
}

export function influenceClasses(entries: InfluenceEntry[]): Set<InfluenceClass> {
  return new Set(entries.map((e) => e.cls));
}
