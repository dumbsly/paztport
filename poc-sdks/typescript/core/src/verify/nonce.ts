// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { writeWire } from "../encoding/jcs.ts";

/**
 * A chain's key in the replay cache: the JCS text of `parts`, an array of strings (spec verification.md, Freshness and
 * replay). JCS escapes every string and keeps the elements apart, so no part needs a rule against a delimiter. Throws
 * on a part that is not a string, and MalformedJson on one the wire writer refuses: a lone surrogate or a
 * noncharacter.
 */
export function nonceKey(parts: readonly string[]): string {
  for (const part of parts) {
    if (typeof part !== "string") throw new Error("a nonce key part that is not a string");
  }
  return new TextDecoder().decode(writeWire([...parts]));
}

/** Bounded replay cache: remembers keys for ttlMs, evicting expired ones on each call. */
export class NonceCache {
  readonly ttlMs: number;
  private readonly seen = new Map<string, number>();

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  get size(): number {
    return this.seen.size;
  }

  /** Returns true if key was already recorded (and not expired); records it otherwise. */
  seenBefore(key: string, nowMs: number): boolean {
    for (const [k, t] of this.seen) {
      if (nowMs - t > this.ttlMs) {
        this.seen.delete(k);
      }
    }
    if (this.seen.has(key)) {
      return true;
    }
    this.seen.set(key, nowMs);
    return false;
  }
}
