// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { parseStampsV3, signStampV3, signingBytesV3 } from "../../src/stamp/stamp.ts";

const key = generateKeyPair().privateKey;
const F = { svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: "mcp:github.create_pull_request", bind: "bind-1", infl: "infl-1", prev: "prev-1" };
const v3stamp = signStampV3(F, key);

describe("stamp v3", () => {
  it("signingBytesV3 is the ten fields joined by |, version first", () => {
    expect(Buffer.from(signingBytesV3({ v: 3, ...F })).toString("utf8"))
      .toBe("3|pi|pi-1|rid-1|1767225600000|sess-1|mcp:github.create_pull_request|bind-1|infl-1|prev-1");
  });
  it("refuses | and lone surrogates in rcv", () => {
    expect(() => signingBytesV3({ v: 3, ...F, rcv: "a|b" })).toThrow("stamp field rcv must not contain '|'");
    expect(() => signingBytesV3({ v: 3, ...F, rcv: "\uD800" })).toThrow("lone surrogate");
  });
  it("parseStampsV3 takes only v3 stamps with a string rcv", () => {
    const s = signStampV3(F, key);
    expect(parseStampsV3([s])).toEqual([s]);
    expect(() => parseStampsV3([{ ...s, v: 2 }])).toThrow();
    const { rcv: _r, ...noRcv } = s;
    expect(() => parseStampsV3([noRcv])).toThrow();
    expect(() => parseStampsV3([{ ...s, rcv: 1 }])).toThrow();
  });
  it("parseStampsV3 refuses a stamp whose v is not 3, an empty chain and a non-array", () => {
    for (const v of [1, 2, 4]) {
      expect(() => parseStampsV3([{ ...v3stamp, v }])).toThrow();
      expect(() => parseStampsV3([v3stamp, { ...v3stamp, v }])).toThrow();
      expect(() => parseStampsV3([{ ...v3stamp, v }, v3stamp])).toThrow();
    }
    expect(() => parseStampsV3([])).toThrow();
    expect(() => parseStampsV3("x")).toThrow();
  });
});
