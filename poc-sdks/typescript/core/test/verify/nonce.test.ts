// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import { NonceCache, nonceKey } from "../../src/verify/nonce.ts";

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

describe("nonceKey", () => {
  it("isTheJcsTextOfTheArray", () => {
    expect(nonceKey(["rid-1", "call-1", "req"])).toBe('["rid-1","call-1","req"]');
    expect(nonceKey(["é", "\u0001"])).toBe('["é","\\u0001"]');
  });
  it("escapesAQuoteSoNoTwoKeysShareTheirText", () => {
    expect(nonceKey(['a"b', "c"])).toBe('["a\\"b","c"]');
    expect(nonceKey(["a", "b|c"])).not.toBe(nonceKey(["a|b", "c"]));
    expect(nonceKey(['a","b'])).not.toBe(nonceKey(["a", "b"]));
  });
  it("throwsWhereTheWriterRefuses", () => {
    expect(() => nonceKey(["rid-\uD800", "c", "req"])).toThrow(MalformedJson);
    expect(() => nonceKey(["rid-￾", "c", "req"])).toThrow(MalformedJson);
    expect(() => nonceKey(["rid", 5 as unknown as string])).toThrow("not a string");
  });
});
