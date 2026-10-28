// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../src/b64url.ts";
import { generateKeyPair, sha256, utf8 } from "../src/crypto.ts";
import * as core from "../src/index.ts";
import { signKeyring, verifyKeyring } from "../src/keyring.ts";
import { renewRoot, rootSigningBytes, signRoot, verifyRoot, type SignedRoot } from "../src/root.ts";
import { isCurrent } from "../src/validity.ts";

const POLICY = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const ROOT = sha256(utf8("root"));

const newForm = () => signRoot(ROOT, "v1", POLICY.privateKey, NOT_AFTER);
const oldForm = () => signRoot(ROOT, "v1", POLICY.privateKey);
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
    for (const name of ["signRoot", "renewRoot", "rootSigningBytes", "verifyRoot", "isCurrent"]) expect(name in core, name).toBe(true);
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
