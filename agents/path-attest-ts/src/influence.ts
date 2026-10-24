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

/** Sorts by h, then cls, then src, and removes exact duplicates. */
export function normalizeInfluence(entries: InfluenceEntry[]): InfluenceEntry[] {
  const sorted = entries
    .map((e): InfluenceEntry => (e.cid === undefined ? { cls: e.cls, src: e.src, h: e.h } : { cls: e.cls, src: e.src, h: e.h, cid: e.cid }))
    .sort((a, b) => cmp(a.h, b.h) || cmp(a.cls, b.cls) || cmp(a.src, b.src) || cmp(a.cid ?? "", b.cid ?? ""));
  return sorted.filter((e, i) => i === 0 || canonicalize(e) !== canonicalize(sorted[i - 1]));
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
