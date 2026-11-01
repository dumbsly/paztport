// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair, utf8 } from "../../src/crypto/crypto.ts";
import { printFile } from "../../src/encoding/json-file.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import {
  readReplyCertFile, signReplyCert, replyCertSigningBytes, verifyReplyCert,
} from "../../src/session/reply-cert.ts";
import * as core from "../../src/index.ts";

const POLICY = generateKeyPair();
const OTHER = generateKeyPair();
const ENTRY = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

const issued = () => signReplyCert(POLICY.publicKey, "mcp-entry", ENTRY.publicKey, NOT_AFTER, POLICY.privateKey);

describe("reply certificate", () => {
  it("signs the four fields under a domain prefix", () => {
    expect(Buffer.from(replyCertSigningBytes("P", "s", "K", NOT_AFTER)).toString("utf8")).toBe(
      'paztport-reply-cert\n{"key":"K","notAfter":1798761600000,"policy":"P","svc":"s"}',
    );
    expect(Buffer.from(replyCertSigningBytes("P", "s", "K", MAX_SAFE)).toString("utf8")).toBe(
      'paztport-reply-cert\n{"key":"K","notAfter":9007199254740991,"policy":"P","svc":"s"}',
    );
  });

  it("is exported from the core", () => {
    for (const name of ["signReplyCert", "replyCertSigningBytes", "verifyReplyCert"]) {
      expect(name in core, name).toBe(true);
    }
  });

  it("an issued certificate verifies under its policy key", () => {
    const c = issued();
    expect(c).toEqual({ policy: POLICY.publicKey, svc: "mcp-entry", key: ENTRY.publicKey, notAfter: NOT_AFTER, sig: c.sig });
    expect(verifyReplyCert(c, POLICY.publicKey)).toBe(true);
  });

  it("a tampered notAfter, svc or key fails", () => {
    const c = issued();
    expect(verifyReplyCert({ ...c, notAfter: c.notAfter + 1 }, POLICY.publicKey)).toBe(false);
    expect(verifyReplyCert({ ...c, svc: "github-tools" }, POLICY.publicKey)).toBe(false);
    expect(verifyReplyCert({ ...c, key: OTHER.publicKey }, POLICY.publicKey)).toBe(false);
  });

  it("one signed by another policy key fails", () => {
    const forged = signReplyCert(POLICY.publicKey, "mcp-entry", ENTRY.publicKey, NOT_AFTER, OTHER.privateKey);
    expect(verifyReplyCert(forged, POLICY.publicKey)).toBe(false);
  });

  it("one whose policy is not the pin fails", () => {
    const other = signReplyCert(OTHER.publicKey, "mcp-entry", ENTRY.publicKey, NOT_AFTER, OTHER.privateKey);
    expect(verifyReplyCert(other, OTHER.publicKey)).toBe(true);
    expect(verifyReplyCert(other, POLICY.publicKey)).toBe(false);
  });

  it("other fields are ignored and unsigned", () => {
    const c = { ...issued(), note: "not signed" };
    expect(verifyReplyCert(c, POLICY.publicKey)).toBe(true);
  });

  it("malformed input never throws", () => {
    const c = issued();
    for (const bad of [
      { ...c, sig: "!" },
      { ...c, sig: undefined },
      { ...c, notAfter: -1 },
      { ...c, notAfter: MAX_SAFE + 1 },
      { ...c, notAfter: 1.5 },
      { ...c, notAfter: String(c.notAfter) },
      { ...c, svc: "x\ud800" },
      null,
      undefined,
      "cert",
      [],
    ]) {
      expect(verifyReplyCert(bad as never, POLICY.publicKey)).toBe(false);
    }
    expect(verifyReplyCert(c, "!")).toBe(false);
    expect(verifyReplyCert(c, undefined as never)).toBe(false);
  });

  it("issuing refuses an out-of-range notAfter", () => {
    for (const bad of [-1, MAX_SAFE + 1, 1.5, Number.NaN]) {
      expect(() => signReplyCert(POLICY.publicKey, "mcp-entry", ENTRY.publicKey, bad, POLICY.privateKey)).toThrow();
      expect(() => replyCertSigningBytes("P", "s", "K", bad)).toThrow();
    }
  });
});

describe("readReplyCertFile", () => {
  const malformed = (read: () => unknown) => {
    try {
      read();
    } catch (e) {
      return e as Error;
    }
    throw new Error("read");
  };

  it("a file in any member order and spacing loads", () => {
    const c = issued();
    for (const text of [JSON.stringify(c, null, 2), printFile(c)]) {
      const read = readReplyCertFile(utf8(text));
      expect(read).toEqual(c);
      expect(verifyReplyCert(read, POLICY.publicKey)).toBe(true);
    }
  });

  it("a notAfter written with a fraction is malformed", () => {
    const text = printFile(issued()).replace(`${NOT_AFTER},`, `${NOT_AFTER}.0,`);
    expect(text).toContain("1798761600000.0");
    const e = malformed(() => readReplyCertFile(utf8(text)));
    expect(e).toBeInstanceOf(MalformedJson);
    expect((e as MalformedJson).step).toBe("parse");
  });

  it("an extra member is malformed", () => {
    const text = printFile({ ...issued(), note: "not signed" });
    expect(malformed(() => readReplyCertFile(utf8(text))).message).toBe("a member the object does not define");
  });

  it("refuses each member missing, naming it", () => {
    const c = issued();
    for (const name of ["key", "notAfter", "policy", "sig", "svc"]) {
      const { [name as keyof typeof c]: _gone, ...rest } = c;
      expect(malformed(() => readReplyCertFile(utf8(printFile(rest)))).message, name).toBe(`no member ${name}`);
    }
  });

  it("is exported from the core", () => expect("readReplyCertFile" in core).toBe(true));
});
