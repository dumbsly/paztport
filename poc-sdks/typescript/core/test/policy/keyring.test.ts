// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, utf8 } from "../../src/crypto/crypto.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { canonicalize } from "../../src/encoding/jcs.ts";
import * as core from "../../src/index.ts";
import { keyringSigningBytes, signKeyring, verifyKeyring, type SignedKeyring } from "../../src/policy/keyring.ts";
import { signRoot, verifyRoot } from "../../src/policy/root.ts";
import { isCurrent } from "../../src/policy/validity.ts";

const POLICY = generateKeyPair();
const OTHER = generateKeyPair();
const NOT_AFTER = 1_798_761_600_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const SERVICES = { pi: generateKeyPair().publicKey };

const signed = () => signKeyring(SERVICES, POLICY.publicKey, POLICY.privateKey, NOT_AFTER);
/** A keyring with no notAfter, signed by the policy key over its other fields alone. */
const unwindowed = () => ({
  policy: POLICY.publicKey,
  services: SERVICES,
  sig: encode(sign(POLICY.privateKey, utf8("paztport-keyring\n" + canonicalize({ policy: POLICY.publicKey, services: SERVICES })))),
}) as unknown as SignedKeyring;
const text = (b: Uint8Array) => Buffer.from(b).toString("utf8");

describe("keyring", () => {
  it("verifies only the signed services under the named policy key", () => {
    const p = generateKeyPair();
    const k = signKeyring({ a: "A" }, p.publicKey, p.privateKey, NOT_AFTER);
    expect(verifyKeyring(k, p.publicKey)).toBe(true);
    expect(verifyKeyring({ ...k, services: { a: "B" } }, p.publicKey)).toBe(false);
    expect(verifyKeyring(k, generateKeyPair().publicKey)).toBe(false);
    expect(verifyKeyring({ ...k, sig: "!" }, p.publicKey)).toBe(false);
  });

  it("signs the window, the policy key and services under a domain prefix", () => {
    expect(text(keyringSigningBytes("P", { a: "K" }, NOT_AFTER))).toBe('paztport-keyring\n{"notAfter":1798761600000,"policy":"P","services":{"a":"K"}}');
    expect(text(keyringSigningBytes("P", {}, MAX_SAFE))).toBe('paztport-keyring\n{"notAfter":9007199254740991,"policy":"P","services":{}}');
    for (const bad of [-1, MAX_SAFE + 1, 1.5, Number.NaN, undefined]) expect(() => keyringSigningBytes("P", {}, bad as number), String(bad)).toThrow(TypeError);
  });

  it("is exported from the core", () => {
    for (const name of ["signKeyring", "keyringSigningBytes", "verifyKeyring"]) expect(name in core, name).toBe(true);
  });

  it("signKeyring signs only with a window", () => {
    for (const bad of [undefined, null, 1.5, -1, MAX_SAFE + 1, "1798761600000"]) {
      expect(() => signKeyring(SERVICES, POLICY.publicKey, POLICY.privateKey, bad as unknown as number), String(bad)).toThrow(TypeError);
    }
  });

  it("roundTrip", () => {
    const k = signed();
    expect(Object.keys(k)).toEqual(["policy", "services", "sig", "notAfter"]);
    expect(k).toEqual({ policy: POLICY.publicKey, services: SERVICES, sig: k.sig, notAfter: NOT_AFTER });
    expect(verifyKeyring(k, POLICY.publicKey)).toBe(true);
    expect(verifyKeyring(k, OTHER.publicKey)).toBe(false);
    const parsed = JSON.parse(JSON.stringify(k)) as SignedKeyring;
    expect(verifyKeyring(parsed, POLICY.publicKey)).toBe(true);
  });

  it("tamperedNotAfterFails", () => {
    const k = signed();
    expect(verifyKeyring({ ...k, notAfter: NOT_AFTER + 1 }, POLICY.publicKey)).toBe(false);
    expect(verifyKeyring({ ...k, services: { pi: OTHER.publicKey } }, POLICY.publicKey)).toBe(false);
  });

  it("a window is never lent to a signature that did not cover one", () => {
    expect(verifyKeyring({ ...unwindowed(), notAfter: NOT_AFTER }, POLICY.publicKey)).toBe(false);
  });

  it("a notAfter that is not an integer in range fails", () => {
    for (const base of [signed(), unwindowed()]) {
      for (const bad of [1.5, -1, MAX_SAFE + 1, "1798761600000", null, undefined, true, {}, []]) {
        expect(verifyKeyring({ ...base, notAfter: bad } as unknown as SignedKeyring, POLICY.publicKey), String(bad)).toBe(false);
      }
    }
  });

  it("currentAtNotAfter", () => {
    const k = signed();
    expect(isCurrent(k, NOT_AFTER - 1)).toBe(true);
    expect(isCurrent(k, NOT_AFTER)).toBe(true);
    expect(isCurrent(k, NOT_AFTER + 1)).toBe(false);
  });

  it("crossPrefix", () => {
    const root = signRoot(new Uint8Array(32), "v1", POLICY.privateKey, NOT_AFTER);
    expect(verifyKeyring({ ...signed(), sig: root.sig }, POLICY.publicKey), "a root signature as a keyring's").toBe(false);
    expect(verifyRoot({ ...root, sig: signed().sig }, POLICY.publicKey), "a keyring signature as a root's").toBe(false);
  });

  it("protoNotAfterIgnored", () => {
    // An inherited notAfter is not the keyring's own, so it neither verifies nor makes the keyring current.
    const inheriting = (k: object) => Object.assign(Object.create({ notAfter: NOT_AFTER }) as SignedKeyring, k);
    const { notAfter: _n, ...stripped } = signed();
    for (const k of [inheriting(stripped), inheriting(unwindowed())]) {
      expect(k.notAfter).toBe(NOT_AFTER);
      expect(verifyKeyring(k, POLICY.publicKey)).toBe(false);
      expect(isCurrent(k, 0)).toBe(false);
    }
  });

  it("verify never throws", () => {
    for (const bad of [null, undefined, 1, "x", [], {}, { ...signed(), services: null }, { ...signed(), sig: 1 }]) {
      expect(verifyKeyring(bad as unknown as SignedKeyring, POLICY.publicKey)).toBe(false);
    }
  });
  it("a keyring without notAfter never verifies and is never current, though signed over its other fields", () => {
    const k = unwindowed();
    expect(verifyKeyring(k, POLICY.publicKey)).toBe(false);
    expect(isCurrent(k, 0)).toBe(false);
  });
});
