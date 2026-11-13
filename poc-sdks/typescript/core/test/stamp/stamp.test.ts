// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, utf8, verify } from "../../src/crypto/crypto.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import { readChain, signStamp, signingBytes } from "../../src/stamp/stamp.ts";

const { privateKey: key, publicKey } = generateKeyPair();
const F = { svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: "mcp:github.create_pull_request", bind: "bind-1", ext: "ext-1", prev: "prev-1" };
const stamp = signStamp(F, key);

/**
 * A token of `value`'s JCS bytes, written by the hashing rules, so a value no protocol writer writes still reaches
 * the reader.
 */
const token = (value: unknown): string => encode(utf8(canonicalize(value)));

describe("stamp", () => {
  it("signedBytesAreThePrefixThenTheJcsOfTheTenMembers", () => {
    // the spec's worked example (wire.md, Fields and signed bytes)
    const s = { v: 4 as const, svc: "pi", inst: "pi-é", rid: "rid-1", ts: 1767225600000, sess: "", rcv: "local:read", bind: "bind-2", ext: "", prev: "prev-2" };
    const text = 'paztport-stamp\n{"bind":"bind-2","ext":"","inst":"pi-é","prev":"prev-2","rcv":"local:read","rid":"rid-1","sess":"","svc":"pi","ts":1767225600000,"v":4}';
    expect(Buffer.from(signingBytes(s))).toEqual(Buffer.from(text, "utf8"));
    expect(Buffer.from(signingBytes(s)).includes(Buffer.from([0x0a, 0x7b]))).toBe(true);
    expect(Buffer.from(signingBytes(s)).includes(Buffer.from([0xc3, 0xa9]))).toBe(true);
  });
  it("signingBytesLeaveTheSignatureOut", () => {
    expect(signingBytes(stamp)).toEqual(signingBytes({ v: 4, ...F }));
  });
  it("aPipeInAFieldSigns", () => {
    const s = signStamp({ ...F, rid: "a|b" }, key);
    expect(s.rid).toBe("a|b");
    expect(verify(publicKey, signingBytes(s), decode(s.sig))).toBe(true);
  });
  it("refusesALoneSurrogateAndANoncharacter", () => {
    expect(() => signingBytes({ v: 4, ...F, rcv: "\uD800" })).toThrow("stamp field rcv must not contain a lone surrogate or a noncharacter");
    expect(() => signingBytes({ v: 4, ...F, ext: "\uDC00x" })).toThrow("stamp field ext must not contain a lone surrogate");
    expect(() => signStamp({ ...F, inst: "￾" }, key)).toThrow("stamp field inst must not contain a lone surrogate or a noncharacter");
    expect(() => signStamp({ ...F, sess: "﷐" }, key)).toThrow("noncharacter");
    expect(() => signStamp({ ...F, prev: "\u{1FFFF}" }, key)).toThrow("noncharacter");
    expect(() => signingBytes({ v: 4, ...F, inst: "￿" })).toThrow("noncharacter");
  });
  it("signStampRefusesANegativeTs", () => {
    expect(() => signStamp({ ...F, ts: -1 }, key)).toThrow("ts");
    expect(() => signStamp({ ...F, ts: 2 ** 53 }, key)).toThrow("ts");
    expect(() => signStamp({ ...F, ts: 1.5 }, key)).toThrow("ts");
    expect(signStamp({ ...F, ts: 0 }, key).ts).toBe(0);
  });
  it("readChain", () => {
    expect(readChain(writeToken([stamp]))).toEqual([stamp]);
    expect(() => readChain(writeToken([{ ...stamp, v: 3 }]))).toThrow("member v is not 4");
    const { ext, ...noExt } = stamp;
    expect(() => readChain(writeToken([{ ...noExt, infl: ext }]))).toThrow("no member ext");
    expect(() => readChain(writeToken([{ ...stamp, infl: "" }]))).toThrow("a member the object does not define");
  });
  it("readChain takes only stamps with a string rcv and a canonical sig, naming the member it refuses", () => {
    const { rcv: _r, ...noRcv } = stamp;
    expect(() => readChain(writeToken([noRcv]))).toThrow("no member rcv");
    expect(() => readChain(writeToken([{ ...stamp, rcv: 1 }]))).toThrow("member rcv");
    expect(() => readChain(writeToken([{ ...stamp, ext: 1 }]))).toThrow("member ext");
    expect(() => readChain(writeToken([{ ...stamp, extra: 1 }]))).toThrow("a member the object does not define");
    for (const sig of [`${stamp.sig}=`, "!!!", stamp.sig.slice(0, -1)]) {
      expect(() => readChain(writeToken([{ ...stamp, sig }])), sig).toThrow("member sig is not canonical base64url");
    }
  });
  it("readChain refuses a stamp of another version, an empty chain and a non-array", () => {
    for (const v of [1, 2, 3, 5]) {
      expect(() => readChain(writeToken([{ ...stamp, v }]))).toThrow();
      expect(() => readChain(writeToken([stamp, { ...stamp, v }]))).toThrow();
      expect(() => readChain(writeToken([{ ...stamp, v }, stamp]))).toThrow();
    }
    expect(() => readChain(writeToken([]))).toThrow();
    expect(() => readChain(writeToken("x"))).toThrow();
  });
  it("readChain refuses bytes that do not read: a negative or fractional ts, a noncharacter, a non-JCS order", () => {
    const tokens = [
      token([{ ...stamp, ts: -1 }]), token([{ ...stamp, ts: 1.5 }]), token([{ ...stamp, inst: "pi-﷐" }]),
    ];
    for (const t of tokens) {
      expect(() => readChain(t)).toThrow(MalformedJson);
    }
    const reordered = `[{"v":4,${canonicalize(stamp).slice(1).replace(',"v":4}', "}")}]`;
    expect(() => readChain(encode(utf8(reordered)))).toThrow(MalformedJson);
    expect(() => readChain("not*base64url")).toThrow(MalformedJson);
  });
  it("theVersionIsWrittenOnce", () => {
    const src = new URL("../../src/", import.meta.url);
    const files = readdirSync(src, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
    expect(files).toContain("stamp/stamp.ts");
    for (const f of files.filter((f) => f !== "stamp/stamp.ts")) {
      expect(readFileSync(new URL(f, src), "utf8"), f).not.toMatch(/\bv: [34]\b/);
    }
    // in stamp.ts itself, the only code lines that write a 3 or a 4 are the constant and the type's member
    const code = readFileSync(new URL("stamp/stamp.ts", src), "utf8").split("\n").filter((l) => !/^\s*(\/\/|\/\*\*?|\*)/.test(l));
    expect(code.filter((l) => /\b[34]\b/.test(l)).map((l) => l.trim())).toEqual(["export const STAMP_VERSION = 4;", "v: 4;"]);
  });
});
