// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResult,
  influenceClasses,
  influenceEntry,
  type InfluenceClass,
  type InfluenceEntry,
} from "@paztport/core";

/**
 * Hash of a tool result for influence entries: the library's bindResult,
 * b64url(SHA-256("result\n" + JCS(result without "_meta"))), which equals the
 * server's attested resultHash.
 */
export function contentHash(result: Record<string, unknown>): string {
  return bindResult(result);
}

/** Influence accumulated over a pi session. Sticky until reset(). */
export class InfluenceStore {
  private all: InfluenceEntry[] = [];

  /**
   * Every entry, in the order recorded, repeats kept: a request commits to its block as written, so the store does
   * not reorder or merge. A fresh array on every call.
   */
  entries(): InfluenceEntry[] {
    return [...this.all];
  }

  /** What a tool result's reading adds (the SDK's `responseEntries`), appended as given. */
  add(entries: readonly InfluenceEntry[]): void {
    this.all.push(...entries);
  }

  /**
   * One entry per class, with no cid, each with the source as given: `local:<tool>` for the labels the local gate
   * read for a built-in tool's result, live and when a session branch is restored, and `server:<id>` for the classes
   * a restored server result added (its details' `added`), whose cids the branch does not keep.
   */
  recordClasses(src: string, classes: InfluenceClass[], contentHash: string): void {
    for (const cls of classes) {
      this.all.push(influenceEntry(cls, src, contentHash));
    }
  }

  recordUntrusted(src: string, contentHash: string): void {
    this.all.push(influenceEntry("local-untrusted", src, contentHash));
  }

  /** Content whose sources cannot be traced, so it may hold anything: private and local-untrusted. */
  recordUnknown(src: string, contentHash: string): void {
    this.all.push(influenceEntry("private", src, contentHash), influenceEntry("local-untrusted", src, contentHash));
  }

  classes(): Set<InfluenceClass> {
    return influenceClasses(this.all);
  }

  /** Entry count per class, every entry counted, every class present (0 when absent). Never carries hashes, cids, srcs or content. */
  summary(): Record<InfluenceClass, number> {
    const out: Record<InfluenceClass, number> = { "third-party": 0, private: 0, public: 0, "local-untrusted": 0 };
    for (const e of this.all) {
      out[e.cls] += 1;
    }
    return out;
  }

  reset(): void {
    this.all = [];
  }
}
