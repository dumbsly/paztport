// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import * as core from "../../src/index.ts";
import { keyringSigningBytes, renewKeyring, signKeyring, signKeyringOldForm, verifyKeyring, type SignedKeyring } from "../../src/policy/keyring.ts";
import { signRoot, verifyRoot } from "../../src/policy/root.ts";
import { isCurrent } from "../../src/policy/validity.ts";

const POLICY = generateKeyPair();
const OTHER = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const SERVICES = { pi: generateKeyPair().publicKey };

const newForm = () => signKeyring(SERVICES, POLICY.publicKey, POLICY.privateKey, NOT_AFTER);
const oldForm = () => signKeyringOldForm(SERVICES, POLICY.publicKey, POLICY.privateKey);
const text = (b: Uint8Array) => Buffer.from(b).toString("utf8");

describe("keyring", () => {
  it("signs the policy key and services under a domain prefix", () => {
    expect(Buffer.from(keyringSigningBytes("P", { a: "A" })).toString("utf8")).toBe('paztport-keyring\n{"policy":"P","services":{"a":"A"}}');
  });
  it("verifies only the signed services under the named policy key", () => {
    const p = generateKeyPair();
    const k = signKeyringOldForm({ a: "A" }, p.publicKey, p.privateKey);
    expect(verifyKeyring(k, p.publicKey)).toBe(true);
    expect(verifyKeyring({ ...k, services: { a: "B" } }, p.publicKey)).toBe(false);
    expect(verifyKeyring(k, generateKeyPair().publicKey)).toBe(false);
    expect(verifyKeyring({ ...k, sig: "!" }, p.publicKey)).toBe(false);
  });

  it("signs the new form's window under the same prefix", () => {
    expect(text(keyringSigningBytes("P", { a: "K" }, NOT_AFTER))).toBe('paztport-keyring\n{"notAfter":1798761600000,"policy":"P","services":{"a":"K"}}');
    expect(text(keyringSigningBytes("P", {}, MAX_SAFE))).toBe('paztport-keyring\n{"notAfter":9007199254740991,"policy":"P","services":{}}');
    expect(text(keyringSigningBytes("P", { a: "K" }))).toBe('paztport-keyring\n{"policy":"P","services":{"a":"K"}}');
    for (const bad of [-1, MAX_SAFE + 1, 1.5, Number.NaN]) expect(() => keyringSigningBytes("P", {}, bad), String(bad)).toThrow(TypeError);
  });

  it("is exported from the core", () => {
    for (const name of ["signKeyring", "signKeyringOldForm", "renewKeyring", "keyringSigningBytes", "verifyKeyring"]) expect(name in core, name).toBe(true);
  });

  it("signKeyring signs only the new form, so a missing window never yields the old form", () => {
    for (const bad of [undefined, null, 1.5, -1, MAX_SAFE + 1, "1798761600000"]) {
      expect(() => signKeyring(SERVICES, POLICY.publicKey, POLICY.privateKey, bad as unknown as number), String(bad)).toThrow(TypeError);
    }
    expect(Object.hasOwn(oldForm(), "notAfter")).toBe(false);
    expect(verifyKeyring(oldForm(), POLICY.publicKey)).toBe(true);
  });

  it("newFormRoundTrip", () => {
    const k = newForm();
    expect(Object.keys(k)).toEqual(["policy", "services", "sig", "notAfter"]);
    expect(k).toEqual({ policy: POLICY.publicKey, services: SERVICES, sig: k.sig, notAfter: NOT_AFTER });
    expect(verifyKeyring(k, POLICY.publicKey)).toBe(true);
    expect(verifyKeyring(k, OTHER.publicKey)).toBe(false);
    const parsed = JSON.parse(JSON.stringify(k)) as SignedKeyring;
    expect(verifyKeyring(parsed, POLICY.publicKey)).toBe(true);
  });

  it("tamperedNotAfterFails", () => {
    const k = newForm();
    expect(verifyKeyring({ ...k, notAfter: NOT_AFTER + 1 }, POLICY.publicKey)).toBe(false);
    expect(verifyKeyring({ ...k, services: { pi: OTHER.publicKey } }, POLICY.publicKey)).toBe(false);
  });

  it("neither form passes for the other", () => {
    const { notAfter: _n, ...dropped } = newForm();
    expect(verifyKeyring(dropped, POLICY.publicKey), "dropping notAfter must not turn a new-form signature into an old-form one").toBe(false);
    expect(verifyKeyring({ ...oldForm(), notAfter: NOT_AFTER }, POLICY.publicKey), "adding notAfter must not lend an old-form signature a window").toBe(false);
  });

  it("a present notAfter that is not an integer in range fails, never read as absent", () => {
    for (const base of [newForm(), oldForm()]) {
      for (const bad of [1.5, -1, MAX_SAFE + 1, "1798761600000", null, undefined, true, {}, []]) {
        expect(verifyKeyring({ ...base, notAfter: bad } as unknown as SignedKeyring, POLICY.publicKey), String(bad)).toBe(false);
      }
    }
  });

  it("oldFormStillVerifies", () => {
    const old = oldForm();
    expect(Object.keys(old)).toEqual(["policy", "services", "sig"]);
    expect(verifyKeyring(old, POLICY.publicKey)).toBe(true);
    expect(JSON.stringify(old)).not.toContain("notAfter");
    expect(isCurrent(old, 0)).toBe(false);
  });

  it("currentAtNotAfter", () => {
    const k = newForm();
    expect(isCurrent(k, NOT_AFTER - 1)).toBe(true);
    expect(isCurrent(k, NOT_AFTER)).toBe(true);
    expect(isCurrent(k, NOT_AFTER + 1)).toBe(false);
    expect(isCurrent(oldForm(), Number.MIN_SAFE_INTEGER)).toBe(false);
  });

  it("renewKeepsServices", () => {
    const renewed = renewKeyring(oldForm(), NOT_AFTER + 5, POLICY.privateKey);
    expect(renewed).toEqual({ policy: POLICY.publicKey, services: SERVICES, sig: renewed.sig, notAfter: NOT_AFTER + 5 });
    expect(verifyKeyring(renewed, POLICY.publicKey)).toBe(true);
    expect(renewKeyring(newForm(), NOT_AFTER + 9, POLICY.privateKey)).toEqual(signKeyring(SERVICES, POLICY.publicKey, POLICY.privateKey, NOT_AFTER + 9));
  });

  it("crossPrefix", () => {
    const root = signRoot(new Uint8Array(32), "v1", POLICY.privateKey, NOT_AFTER);
    expect(verifyKeyring({ ...newForm(), sig: root.sig }, POLICY.publicKey), "a root signature as a keyring's").toBe(false);
    expect(verifyRoot({ ...root, sig: newForm().sig }, POLICY.publicKey), "a keyring signature as a root's").toBe(false);
  });

  it("protoNotAfterIgnored", () => {
    // An inherited notAfter is not the keyring's own, so it neither lends an old-form keyring a window nor makes one current.
    const inheriting = (k: SignedKeyring) => Object.assign(Object.create({ notAfter: NOT_AFTER }) as SignedKeyring, k);
    const old = inheriting(oldForm());
    expect(old.notAfter).toBe(NOT_AFTER);
    expect(verifyKeyring(old, POLICY.publicKey)).toBe(true);
    expect(isCurrent(old, 0)).toBe(false);
    const { notAfter: _n, ...stripped } = newForm();
    expect(verifyKeyring(inheriting(stripped), POLICY.publicKey)).toBe(false);
  });

  it("verify never throws", () => {
    for (const bad of [null, undefined, 1, "x", [], {}, { ...newForm(), services: null }, { ...newForm(), sig: 1 }]) {
      expect(verifyKeyring(bad as unknown as SignedKeyring, POLICY.publicKey)).toBe(false);
    }
  });
});
