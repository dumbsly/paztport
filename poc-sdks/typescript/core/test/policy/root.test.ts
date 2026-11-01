// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, sha256, sign, utf8 } from "../../src/crypto/crypto.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { printFile } from "../../src/encoding/json-file.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import * as core from "../../src/index.ts";
import { signKeyring, verifyKeyring } from "../../src/policy/keyring.ts";
import { signReplyCert, verifyReplyCert } from "../../src/session/reply-cert.ts";
import {
  readRoot, readRootFile, signRenewedRoot, rootSigningBytes, signRoot, verifyRoot, type SignedRoot,
} from "../../src/policy/root.ts";
import { earliestNotAfter, isCurrent, readNotAfter } from "../../src/policy/validity.ts";

const POLICY = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const ROOT = sha256(utf8("root"));

const signed = () => signRoot(ROOT, "v1", POLICY.privateKey, NOT_AFTER);
/** A root with no notAfter, signed by the policy key over `rootId|root`. */
const unwindowed = () => ({ rootId: "v1", root: encode(ROOT), sig: encode(sign(POLICY.privateKey, utf8(`v1|${encode(ROOT)}`))) }) as unknown as SignedRoot;
const text = (b: Uint8Array) => Buffer.from(b).toString("utf8");

describe("signed root", () => {
  it("signs under its own domain prefix", () => {
    expect(text(rootSigningBytes("v1", "R", NOT_AFTER))).toBe('paztport-root\n{"notAfter":1798761600000,"root":"R","rootId":"v1"}');
    expect(text(rootSigningBytes("v1", "R", MAX_SAFE))).toBe('paztport-root\n{"notAfter":9007199254740991,"root":"R","rootId":"v1"}');
    for (const bad of [-1, MAX_SAFE + 1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, undefined]) {
      expect(() => rootSigningBytes("v1", "R", bad as number), String(bad)).toThrow(TypeError);
    }
  });

  it("is exported from the core", () => {
    for (const name of ["signRoot", "signRenewedRoot", "rootSigningBytes", "verifyRoot", "isCurrent"]) {
      expect(name in core, name).toBe(true);
    }
  });

  it("signRoot signs only with a window", () => {
    for (const bad of [undefined, null, 1.5, -1, MAX_SAFE + 1, "1798761600000"]) {
      expect(() => signRoot(ROOT, "v1", POLICY.privateKey, bad as unknown as number), String(bad)).toThrow(TypeError);
    }
  });

  it("roundTrip", () => {
    const r = signed();
    expect(Object.keys(r)).toEqual(["rootId", "root", "sig", "notAfter"]);
    expect(r).toEqual({ rootId: "v1", root: encode(ROOT), sig: r.sig, notAfter: NOT_AFTER });
    expect(verifyRoot(r, POLICY.publicKey)).toBe(true);
    expect(verifyRoot(r, generateKeyPair().publicKey)).toBe(false);
    const parsed = JSON.parse(JSON.stringify(r)) as SignedRoot;
    expect(parsed).toEqual(r);
    expect(verifyRoot(parsed, POLICY.publicKey)).toBe(true);
    expect(verifyRoot(JSON.parse(JSON.stringify(r).replace('"notAfter":1798761600000', '"notAfter":1798761600000.0')), POLICY.publicKey)).toBe(true);
  });

  it("tamperedNotAfterFails", () => {
    const r = signed();
    expect(verifyRoot({ ...r, notAfter: NOT_AFTER + 1 }, POLICY.publicKey)).toBe(false);
    expect(verifyRoot({ ...r, rootId: "v2" }, POLICY.publicKey)).toBe(false);
    expect(verifyRoot({ ...r, root: encode(sha256(utf8("evil"))) }, POLICY.publicKey)).toBe(false);
  });

  it("a window is never lent to a signature that did not cover one", () => {
    expect(verifyRoot({ ...unwindowed(), notAfter: NOT_AFTER }, POLICY.publicKey)).toBe(false);
  });

  it("a notAfter that is not an integer in range fails", () => {
    const r = signed();
    const old = unwindowed();
    for (const bad of [1.5, -1, MAX_SAFE + 1, "1798761600000", null, undefined, true, {}, []]) {
      expect(verifyRoot({ ...r, notAfter: bad } as unknown as SignedRoot, POLICY.publicKey), String(bad)).toBe(false);
      expect(verifyRoot({ ...old, notAfter: bad } as unknown as SignedRoot, POLICY.publicKey), String(bad)).toBe(false);
      expect(isCurrent({ notAfter: bad }, 0), String(bad)).toBe(false);
    }
  });

  it("currentAtNotAfter", () => {
    const r = signed();
    expect(isCurrent(r, NOT_AFTER - 1)).toBe(true);
    expect(isCurrent(r, NOT_AFTER)).toBe(true);
    expect(isCurrent(r, NOT_AFTER + 1)).toBe(false);
    expect(isCurrent(r, Number.NaN)).toBe(false);
    expect(isCurrent(signRoot(ROOT, "v1", POLICY.privateKey, MAX_SAFE), MAX_SAFE)).toBe(true);
    expect(isCurrent(null as unknown as SignedRoot, 0)).toBe(false);
  });

  it("renewKeepsRoot", () => {
    const old = signRoot(ROOT, "v1", POLICY.privateKey, 1000);
    const renewed = signRenewedRoot(old, NOT_AFTER + 5, POLICY.privateKey);
    expect(renewed).toEqual({ rootId: old.rootId, root: old.root, sig: renewed.sig, notAfter: NOT_AFTER + 5 });
    expect(verifyRoot(renewed, POLICY.publicKey)).toBe(true);
    // Renewing signs exactly what signing the tree afresh until that time would.
    expect(signRenewedRoot(signed(), NOT_AFTER + 9, POLICY.privateKey)).toEqual(signRoot(ROOT, "v1", POLICY.privateKey, NOT_AFTER + 9));
    // The root text is reused as it stands, so the renewed root names exactly the tree the old one did.
    const odd = { ...old, root: old.root + "==" };
    expect(signRenewedRoot(odd, NOT_AFTER, POLICY.privateKey).root).toBe(odd.root);
    expect(decode(renewed.root)).toEqual(ROOT);
  });

  it("crossPrefix", () => {
    const services = { pi: generateKeyPair().publicKey };
    const root = signed();
    expect(verifyKeyring({ policy: POLICY.publicKey, services, sig: root.sig, notAfter: root.notAfter }, POLICY.publicKey), "a root signature as a keyring's").toBe(false);
    const ring = signKeyring(services, POLICY.publicKey, POLICY.privateKey, NOT_AFTER);
    expect(verifyRoot({ ...root, sig: ring.sig }, POLICY.publicKey), "a keyring signature as a root's").toBe(false);
  });

  // These would also fail incidentally, since the bodies differ; the literal signing-bytes tests are what pin the prefixes.
  it("crossPrefixReplyCert", () => {
    const root = signed();
    const cert = signReplyCert(POLICY.publicKey, "mcp-entry", generateKeyPair().publicKey, NOT_AFTER, POLICY.privateKey);
    expect(verifyRoot(root, POLICY.publicKey) && verifyReplyCert(cert, POLICY.publicKey)).toBe(true);
    expect(verifyRoot({ ...root, sig: cert.sig }, POLICY.publicKey), "a reply-certificate signature as a root's").toBe(false);
    expect(verifyReplyCert({ ...cert, sig: root.sig }, POLICY.publicKey), "a root signature as a reply certificate's").toBe(false);
  });

  it("protoNotAfterIgnored", () => {
    // An inherited notAfter is not the root's own, so it neither verifies nor makes the root current.
    const inheriting = (r: object) => Object.assign(Object.create({ notAfter: NOT_AFTER }) as SignedRoot, r);
    const { notAfter: _n, ...stripped } = signed();
    for (const r of [inheriting(stripped), inheriting(unwindowed())]) {
      expect(r.notAfter).toBe(NOT_AFTER);
      expect(verifyRoot(r, POLICY.publicKey)).toBe(false);
      expect(isCurrent(r, 0)).toBe(false);
    }
  });

  it("verify never throws", () => {
    const r = signed();
    for (const bad of [null, undefined, 1, "x", [], {}, { ...r, sig: "!!" }, { ...r, sig: null }, { ...r, rootId: 1 }, { ...r, root: undefined }]) {
      expect(verifyRoot(bad as unknown as SignedRoot, POLICY.publicKey)).toBe(false);
    }
    expect(verifyRoot(r, "!!")).toBe(false);
    expect(verifyRoot(r, null as unknown as string)).toBe(false);
  });
  it("a root without notAfter is refused when read and never verifies, though signed over rootId|root", () => {
    const sr = unwindowed();
    expect(() => readRoot(writeToken(sr as unknown as JsonValue))).toThrow("no member notAfter");
    expect(verifyRoot(sr, POLICY.publicKey)).toBe(false);
    expect(isCurrent(sr, 0)).toBe(false);
  });
});

describe("readNotAfter", () => {
  it("reads an own member by value, and refuses one that is missing, inherited or out of range", () => {
    expect(() => readNotAfter({}, "clientKeyringNotAfter")).toThrow(new TypeError("clientKeyringNotAfter must be an integer in [0, 2^53 - 1]"));
    expect(readNotAfter({ clientKeyringNotAfter: NOT_AFTER }, "clientKeyringNotAfter")).toBe(NOT_AFTER);
    expect(readNotAfter(JSON.parse('{"w":1798761600000.0}'), "w")).toBe(NOT_AFTER);
    expect(readNotAfter({ w: 0 }, "w")).toBe(0);
    expect(readNotAfter({ w: MAX_SAFE }, "w")).toBe(MAX_SAFE);
    for (const bad of [1.5, -1, MAX_SAFE + 1, "x", null, undefined, true, {}, []]) {
      expect(() => readNotAfter({ w: bad }, "w"), String(bad)).toThrow(new TypeError("w must be an integer in [0, 2^53 - 1]"));
    }
    expect(() => readNotAfter(Object.create({ w: NOT_AFTER }), "w"), "inherited").toThrow(TypeError);
    expect(core.readNotAfter).toBe(readNotAfter);
  });
});

describe("earliestNotAfter", () => {
  it("is the earliest window", () => {
    expect(earliestNotAfter(NOT_AFTER, NOT_AFTER + 1)).toBe(NOT_AFTER);
    expect(earliestNotAfter(MAX_SAFE, 0)).toBe(0);
    expect(earliestNotAfter(NOT_AFTER)).toBe(NOT_AFTER);
    expect(core.earliestNotAfter).toBe(earliestNotAfter);
  });
});

describe("readRootFile", () => {
  const malformed = (read: () => unknown) => {
    try {
      read();
    } catch (e) {
      return e as Error;
    }
    throw new Error("read");
  };

  it("a file in any member order and spacing loads", () => {
    const r = signed();
    // JSON.stringify's form, members in the object's order with no newline at the end, and Jackson's pretty form
    const stringified = JSON.stringify(r, null, 2);
    const pretty = [
      "{", '  "rootId" : "v1",', `  "root" : "${r.root}",`, `  "sig" : "${r.sig}",`, `  "notAfter" : ${NOT_AFTER}`, "}",
    ].join("\n");
    for (const text of [stringified, pretty, printFile(r)]) {
      const read = readRootFile(utf8(text));
      expect(read).toEqual(r);
      expect(verifyRoot(read, POLICY.publicKey)).toBe(true);
    }
  });

  it("a notAfter written with a fraction is malformed", () => {
    const text = printFile(signed()).replace(`${NOT_AFTER},`, `${NOT_AFTER}.0,`);
    expect(text).toContain("1798761600000.0");
    const e = malformed(() => readRootFile(utf8(text)));
    expect(e).toBeInstanceOf(MalformedJson);
    expect((e as MalformedJson).step).toBe("parse");
  });

  it("an extra member is malformed", () => {
    const text = printFile({ ...signed(), note: "not signed" });
    expect(malformed(() => readRootFile(utf8(text))).message).toBe("a member the object does not define");
  });

  it("refuses each member missing or of another type, naming it", () => {
    const r = signed();
    for (const name of ["notAfter", "root", "rootId", "sig"]) {
      const { [name as keyof SignedRoot]: _gone, ...rest } = r;
      expect(malformed(() => readRootFile(utf8(printFile(rest)))).message, name).toBe(`no member ${name}`);
    }
    const read = (v: object) => malformed(() => readRootFile(utf8(printFile(v as JsonValue)))).message;
    expect(read({ ...r, rootId: 1 })).toBe("member rootId is not a string");
    expect(read({ ...r, notAfter: "1" })).toBe("member notAfter is not an integer");
  });

  it("readRoot reads the root's token, and no other spelling of it", () => {
    const r = signed();
    expect(readRoot(writeToken(r))).toEqual(r);
    const e = malformed(() => readRoot(encode(utf8(printFile(r)))));
    expect((e as MalformedJson).step).toBe("canonical");
  });

  it("are exported from the core", () => {
    for (const name of ["readRootFile", "readRoot"]) expect(name in core, name).toBe(true);
  });
});
