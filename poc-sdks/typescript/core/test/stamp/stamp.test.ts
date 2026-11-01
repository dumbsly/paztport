// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, utf8 } from "../../src/crypto/crypto.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import { readChain, signStampV3, signingBytesV3 } from "../../src/stamp/stamp.ts";

const key = generateKeyPair().privateKey;
const F = { svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: "mcp:github.create_pull_request", bind: "bind-1", infl: "infl-1", prev: "prev-1" };
const v3stamp = signStampV3(F, key);

/**
 * A token of `value`'s JCS bytes, written by the hashing rules, so a value no protocol writer writes still reaches
 * the reader.
 */
const token = (value: unknown): string => encode(utf8(canonicalize(value)));

describe("stamp v3", () => {
  it("signingBytesV3 is the ten fields joined by |, version first", () => {
    expect(Buffer.from(signingBytesV3({ v: 3, ...F })).toString("utf8"))
      .toBe("3|pi|pi-1|rid-1|1767225600000|sess-1|mcp:github.create_pull_request|bind-1|infl-1|prev-1");
  });
  it("refuses | and lone surrogates in rcv", () => {
    expect(() => signingBytesV3({ v: 3, ...F, rcv: "a|b" })).toThrow("stamp field rcv must not contain '|'");
    expect(() => signingBytesV3({ v: 3, ...F, rcv: "\uD800" })).toThrow("lone surrogate");
  });
  it("signStampV3RefusesANoncharacter", () => {
    expect(() => signStampV3({ ...F, inst: "\uFFFE" }, key)).toThrow("noncharacter");
    expect(() => signStampV3({ ...F, sess: "\uFDD0" }, key)).toThrow("noncharacter");
    expect(() => signStampV3({ ...F, prev: "\u{1FFFF}" }, key)).toThrow("noncharacter");
    expect(() => signingBytesV3({ v: 3, ...F, inst: "\uFFFF" })).toThrow("noncharacter");
  });
  it("signStampV3RefusesANegativeTs", () => {
    expect(() => signStampV3({ ...F, ts: -1 }, key)).toThrow("ts");
    expect(() => signStampV3({ ...F, ts: 2 ** 53 }, key)).toThrow("ts");
    expect(() => signStampV3({ ...F, ts: 1.5 }, key)).toThrow("ts");
    expect(signStampV3({ ...F, ts: 0 }, key).ts).toBe(0);
  });
  it("readChain takes only v3 stamps with a string rcv, naming the member it refuses", () => {
    const s = signStampV3(F, key);
    expect(readChain(writeToken([s]))).toEqual([s]);
    expect(() => readChain(writeToken([{ ...s, v: 2 }]))).toThrow("member v");
    const { rcv: _r, ...noRcv } = s;
    expect(() => readChain(writeToken([noRcv]))).toThrow("no member rcv");
    expect(() => readChain(writeToken([{ ...s, rcv: 1 }]))).toThrow("member rcv");
    expect(() => readChain(writeToken([{ ...s, extra: 1 }]))).toThrow("a member the object does not define");
    for (const sig of [`${s.sig}=`, "!!!", s.sig.slice(0, -1)]) {
      expect(() => readChain(writeToken([{ ...s, sig }])), sig).toThrow("member sig is not canonical base64url");
    }
  });
  it("readChain refuses a stamp whose v is not 3, an empty chain and a non-array", () => {
    for (const v of [1, 2, 4]) {
      expect(() => readChain(writeToken([{ ...v3stamp, v }]))).toThrow();
      expect(() => readChain(writeToken([v3stamp, { ...v3stamp, v }]))).toThrow();
      expect(() => readChain(writeToken([{ ...v3stamp, v }, v3stamp]))).toThrow();
    }
    expect(() => readChain(writeToken([]))).toThrow();
    expect(() => readChain(writeToken("x"))).toThrow();
  });
  it("readChain refuses bytes that do not read: a negative or fractional ts, a noncharacter, a non-JCS order", () => {
    const tokens = [
      token([{ ...v3stamp, ts: -1 }]), token([{ ...v3stamp, ts: 1.5 }]), token([{ ...v3stamp, inst: "pi-\uFDD0" }]),
    ];
    for (const t of tokens) {
      expect(() => readChain(t)).toThrow(MalformedJson);
    }
    const reordered = `[{"v":3,${canonicalize(v3stamp).slice(1).replace(',"v":3}', "}")}]`;
    expect(() => readChain(encode(utf8(reordered)))).toThrow(MalformedJson);
    expect(() => readChain("not*base64url")).toThrow(MalformedJson);
  });
});
