// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { parseRecordedStamps, parseStampsV3, signStampV2, signStampV3, signingBytes, signingBytesV3 } from "../../src/stamp/stamp.ts";

const key = generateKeyPair().privateKey;
const F = { svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: "mcp:github.create_pull_request", bind: "bind-1", infl: "infl-1", prev: "prev-1" };
const { rcv: _rcv, ...V2F } = F;
const v2stamp = signStampV2(V2F, key);
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
  it("parseRecordedStamps reads a v2 chain as legacy, a v3 chain as current, and refuses a mixed one", () => {
    expect(parseRecordedStamps([v2stamp]).legacy).toBe(true);
    expect(parseRecordedStamps([v3stamp]).legacy).toBe(false);
    expect(() => parseRecordedStamps([v2stamp, v3stamp])).toThrow();
    expect(() => parseRecordedStamps([])).toThrow();
  });
  it("an rcv on a v2 stamp is not signed, so it is dropped", () => {
    const { stamps, legacy } = parseRecordedStamps([{ ...v2stamp, rcv: "anything" }]);
    expect(legacy).toBe(true);
    expect("rcv" in stamps[0]!).toBe(false);
  });
  it("signingBytes dispatches on the version", () => {
    expect(Buffer.from(signingBytes(v3stamp)).toString("utf8").startsWith("3|")).toBe(true);
    expect(Buffer.from(signingBytes(v2stamp)).toString("utf8").startsWith("2|")).toBe(true);
  });
  it("refuses an unknown version or a non-array", () => {
    expect(() => parseRecordedStamps([{ ...v3stamp, v: 4 }])).toThrow();
    expect(() => parseRecordedStamps("x")).toThrow();
  });
});
