// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/** Bounded replay cache: remembers keys for ttlMs, evicting expired ones on each call. */
export class NonceCache {
  private readonly ttlMs: number;
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
