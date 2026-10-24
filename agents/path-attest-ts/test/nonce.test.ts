// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { NonceCache } from "../src/nonce.ts";

describe("NonceCache", () => {
  it("secondSightIsSeen", () => {
    const c = new NonceCache(5000);
    expect(c.seenBefore("k", 0)).toBe(false);
    expect(c.seenBefore("k", 1)).toBe(true);
  });
  it("evictsAfterTtl", () => {
    const c = new NonceCache(5000);
    expect(c.seenBefore("k", 0)).toBe(false);
    expect(c.size).toBe(1);
    expect(c.seenBefore("other", 5001)).toBe(false);
    expect(c.size).toBe(1);
    expect(c.seenBefore("k", 5001)).toBe(false);
  });
});
