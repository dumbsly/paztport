// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../src/b64url.ts";
import { generateKeyPair, sha256, utf8 } from "../src/crypto.ts";
import * as core from "../src/index.ts";
import { signKeyring, verifyKeyring } from "../src/keyring.ts";
import { issueReplyCert, verifyReplyCert } from "../src/reply-cert.ts";
import { parseSignedRoot, renewRoot, rootSigningBytes, signRoot, signRootOldForm, verifyRoot, type SignedRoot } from "../src/root.ts";
import { earliestNotAfter, isCurrent, readNotAfter } from "../src/validity.ts";

const POLICY = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const ROOT = sha256(utf8("root"));

const newForm = () => signRoot(ROOT, "v1", POLICY.privateKey, NOT_AFTER);
const oldForm = () => signRootOldForm(ROOT, "v1", POLICY.privateKey);
const text = (b: Uint8Array) => Buffer.from(b).toString("utf8");

describe("signed root", () => {
  it("signs the new form under its own domain prefix, and the old form as before", () => {
    expect(text(rootSigningBytes("v1", "R", NOT_AFTER))).toBe('paztport-root\n{"notAfter":1798761600000,"root":"R","rootId":"v1"}');
    expect(text(rootSigningBytes("v1", "R", MAX_SAFE))).toBe('paztport-root\n{"notAfter":9007199254740991,"root":"R","rootId":"v1"}');
    expect(text(rootSigningBytes("v1", "R"))).toBe("v1|R");
    for (const bad of [-1, MAX_SAFE + 1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => rootSigningBytes("v1", "R", bad), String(bad)).toThrow(TypeError);
    }
  });

  it("is exported from the core", () => {
    for (const name of ["signRoot", "signRootOldForm", "renewRoot", "rootSigningBytes", "verifyRoot", "parseSignedRoot", "isCurrent"]) expect(name in core, name).toBe(true);
  });

  it("signRoot signs only the new form, so a missing window never yields the old form", () => {
    for (const bad of [undefined, null, 1.5, -1, MAX_SAFE + 1, "1798761600000"]) {
      expect(() => signRoot(ROOT, "v1", POLICY.privateKey, bad as unknown as number), String(bad)).toThrow(TypeError);
    }
    expect(Object.hasOwn(oldForm(), "notAfter")).toBe(false);
    expect(verifyRoot(oldForm(), POLICY.publicKey)).toBe(true);
  });

  it("parseSignedRoot keeps the root whole, its notAfter included, and refuses a damaged window", () => {
    const r = newForm();
    expect(parseSignedRoot(JSON.parse(JSON.stringify(r)), "clientRoot")).toEqual(r);
    expect(parseSignedRoot(JSON.parse(JSON.stringify(r).replace('"notAfter":1798761600000', '"notAfter":1798761600000.0')), "clientRoot")).toEqual(r);
    const old = parseSignedRoot(JSON.parse(JSON.stringify(oldForm())), "clientRoot");
    expect(Object.hasOwn(old, "notAfter")).toBe(false);
    // extra members are dropped, as the signature does not cover them
    expect(parseSignedRoot({ ...r, note: "x" }, "clientRoot")).toEqual(r);
    for (const bad of [1.5, -1, MAX_SAFE + 1, "x", null, true, {}, []]) {
      expect(() => parseSignedRoot({ ...r, notAfter: bad }, "clientRoot"), String(bad)).toThrow("clientRoot.notAfter must be an integer in [0, 2^53 - 1]");
    }
    expect(() => parseSignedRoot({ ...r, rootId: 1 }, "clientRoot")).toThrow("clientRoot.rootId must be a string");
    expect(() => parseSignedRoot({ ...r, root: undefined }, "clientRoot")).toThrow("clientRoot.root must be a string");
    expect(() => parseSignedRoot({ ...r, sig: null }, "clientRoot")).toThrow("clientRoot.sig must be a string");
    for (const bad of [null, "x", [], 1]) expect(() => parseSignedRoot(bad, "clientRoot"), String(bad)).toThrow("clientRoot must be an object");
    // an inherited notAfter is not the root's own: the result is the old form
    const { notAfter: _w, ...stripped } = r;
    expect(Object.hasOwn(parseSignedRoot(Object.assign(Object.create({ notAfter: NOT_AFTER }), stripped), "clientRoot"), "notAfter")).toBe(false);
  });

  it("newFormRoundTrip", () => {
    const r = newForm();
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
    const r = newForm();
    expect(verifyRoot({ ...r, notAfter: NOT_AFTER + 1 }, POLICY.publicKey)).toBe(false);
    expect(verifyRoot({ ...r, rootId: "v2" }, POLICY.publicKey)).toBe(false);
    expect(verifyRoot({ ...r, root: encode(sha256(utf8("evil"))) }, POLICY.publicKey)).toBe(false);
  });

  it("neither form passes for the other", () => {
    const { notAfter: _n, ...dropped } = newForm();
    expect(verifyRoot(dropped, POLICY.publicKey), "dropping notAfter must not turn a new-form signature into an old-form one").toBe(false);
    expect(verifyRoot({ ...oldForm(), notAfter: NOT_AFTER }, POLICY.publicKey), "adding notAfter must not lend an old-form signature a window").toBe(false);
  });

  it("a present notAfter that is not an integer in range fails, never read as absent", () => {
    const r = newForm();
    const old = oldForm();
    for (const bad of [1.5, -1, MAX_SAFE + 1, "1798761600000", null, undefined, true, {}, []]) {
      expect(verifyRoot({ ...r, notAfter: bad } as unknown as SignedRoot, POLICY.publicKey), String(bad)).toBe(false);
      expect(verifyRoot({ ...old, notAfter: bad } as unknown as SignedRoot, POLICY.publicKey), String(bad)).toBe(false);
      expect(isCurrent({ notAfter: bad }, 0), String(bad)).toBe(false);
    }
  });

  it("oldFormStillVerifies", () => {
    const old = oldForm();
    expect(Object.keys(old)).toEqual(["rootId", "root", "sig"]);
    expect(Object.hasOwn(old, "notAfter")).toBe(false);
    expect(verifyRoot(old, POLICY.publicKey)).toBe(true);
    expect(JSON.stringify(old)).not.toContain("notAfter");
    expect(verifyRoot(JSON.parse(JSON.stringify(old)), POLICY.publicKey)).toBe(true);
    expect(isCurrent(old, 0)).toBe(false);
  });

  it("currentAtNotAfter", () => {
    const r = newForm();
    expect(isCurrent(r, NOT_AFTER - 1)).toBe(true);
    expect(isCurrent(r, NOT_AFTER)).toBe(true);
    expect(isCurrent(r, NOT_AFTER + 1)).toBe(false);
    expect(isCurrent(r, Number.NaN)).toBe(false);
    expect(isCurrent(oldForm(), 0)).toBe(false);
    expect(isCurrent(oldForm(), Number.MIN_SAFE_INTEGER)).toBe(false);
    expect(isCurrent(signRoot(ROOT, "v1", POLICY.privateKey, MAX_SAFE), MAX_SAFE)).toBe(true);
    expect(isCurrent(null as unknown as SignedRoot, 0)).toBe(false);
  });

  it("renewKeepsRoot", () => {
    const old = oldForm();
    const renewed = renewRoot(old, NOT_AFTER + 5, POLICY.privateKey);
    expect(renewed).toEqual({ rootId: old.rootId, root: old.root, sig: renewed.sig, notAfter: NOT_AFTER + 5 });
    expect(verifyRoot(renewed, POLICY.publicKey)).toBe(true);
    // Renewing a new-form root signs exactly what signing the tree afresh until that time would.
    expect(renewRoot(newForm(), NOT_AFTER + 9, POLICY.privateKey)).toEqual(signRoot(ROOT, "v1", POLICY.privateKey, NOT_AFTER + 9));
    // The root text is reused as it stands, so the renewed root names exactly the tree the old one did.
    const odd = { ...old, root: old.root + "==" };
    expect(renewRoot(odd, NOT_AFTER, POLICY.privateKey).root).toBe(odd.root);
    expect(decode(renewed.root)).toEqual(ROOT);
  });

  it("crossPrefix", () => {
    const services = { pi: generateKeyPair().publicKey };
    const root = newForm();
    expect(verifyKeyring({ policy: POLICY.publicKey, services, sig: root.sig, notAfter: root.notAfter }, POLICY.publicKey), "a root signature as a keyring's").toBe(false);
    const ring = signKeyring(services, POLICY.publicKey, POLICY.privateKey, NOT_AFTER);
    expect(verifyRoot({ ...root, sig: ring.sig }, POLICY.publicKey), "a keyring signature as a root's").toBe(false);
  });

  // These would also fail incidentally, since the bodies differ; the literal signing-bytes tests are what pin the prefixes.
  it("crossPrefixReplyCert", () => {
    const root = newForm();
    const cert = issueReplyCert(POLICY.publicKey, "mcp-entry", generateKeyPair().publicKey, NOT_AFTER, POLICY.privateKey);
    expect(verifyRoot(root, POLICY.publicKey) && verifyReplyCert(cert, POLICY.publicKey)).toBe(true);
    expect(verifyRoot({ ...root, sig: cert.sig }, POLICY.publicKey), "a reply-certificate signature as a root's").toBe(false);
    expect(verifyReplyCert({ ...cert, sig: root.sig }, POLICY.publicKey), "a root signature as a reply certificate's").toBe(false);
  });

  it("protoNotAfterIgnored", () => {
    // An inherited notAfter is not the root's own, so it neither lends an old-form root a window nor makes one current.
    const inheriting = (r: SignedRoot) => Object.assign(Object.create({ notAfter: NOT_AFTER }) as SignedRoot, r);
    const old = inheriting(oldForm());
    expect(old.notAfter).toBe(NOT_AFTER);
    expect(verifyRoot(old, POLICY.publicKey)).toBe(true);
    expect(isCurrent(old, 0)).toBe(false);
    const { notAfter: _n, ...stripped } = newForm();
    expect(verifyRoot(inheriting(stripped), POLICY.publicKey)).toBe(false);
  });

  it("verify never throws", () => {
    const r = newForm();
    for (const bad of [null, undefined, 1, "x", [], {}, { ...r, sig: "!!" }, { ...r, sig: null }, { ...r, rootId: 1 }, { ...r, root: undefined }]) {
      expect(verifyRoot(bad as unknown as SignedRoot, POLICY.publicKey)).toBe(false);
    }
    expect(verifyRoot(r, "!!")).toBe(false);
    expect(verifyRoot(r, null as unknown as string)).toBe(false);
  });
});

describe("readNotAfter", () => {
  it("reads an own member by value, absent as undefined, and refuses a present one out of range", () => {
    expect(readNotAfter({}, "clientKeyringNotAfter")).toBeUndefined();
    expect(readNotAfter({ clientKeyringNotAfter: NOT_AFTER }, "clientKeyringNotAfter")).toBe(NOT_AFTER);
    expect(readNotAfter(JSON.parse('{"w":1798761600000.0}'), "w")).toBe(NOT_AFTER);
    expect(readNotAfter({ w: 0 }, "w")).toBe(0);
    expect(readNotAfter({ w: MAX_SAFE }, "w")).toBe(MAX_SAFE);
    for (const bad of [1.5, -1, MAX_SAFE + 1, "x", null, undefined, true, {}, []]) {
      expect(() => readNotAfter({ w: bad }, "w"), String(bad)).toThrow(new TypeError("w must be an integer in [0, 2^53 - 1]"));
    }
    expect(readNotAfter(Object.create({ w: NOT_AFTER }), "w"), "inherited").toBeUndefined();
    expect(core.readNotAfter).toBe(readNotAfter);
  });
});

describe("earliestNotAfter", () => {
  it("is the earliest window, and undefined when any is missing (old form)", () => {
    expect(earliestNotAfter(NOT_AFTER, NOT_AFTER + 1)).toBe(NOT_AFTER);
    expect(earliestNotAfter(MAX_SAFE, 0)).toBe(0);
    expect(earliestNotAfter(NOT_AFTER)).toBe(NOT_AFTER);
    expect(earliestNotAfter(NOT_AFTER, undefined)).toBeUndefined();
    expect(earliestNotAfter(undefined, NOT_AFTER)).toBeUndefined();
    expect(core.earliestNotAfter).toBe(earliestNotAfter);
  });
});
