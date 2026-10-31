// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, isEd25519PublicKey, keyPairMatches, sha256, sign, utf8, verify } from "../../src/crypto/crypto.ts";

describe("crypto", () => {
  it("sha256OfAbc", () => {
    expect(Buffer.from(sha256(utf8("abc"))).toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
  it("signVerifyRoundTrip", () => {
    const kp = generateKeyPair();
    const sig = sign(kp.privateKey, utf8("m"));
    expect(verify(kp.publicKey, utf8("m"), sig)).toBe(true);
    expect(verify(kp.publicKey, utf8("n"), sig)).toBe(false);
  });
  it("verifyFalseOnWrongKey", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(verify(b.publicKey, utf8("m"), sign(a.privateKey, utf8("m")))).toBe(false);
  });
  it("verifyFalseOnGarbageKey", () => {
    expect(verify("not-a-key", utf8("m"), new Uint8Array(64))).toBe(false);
  });
  it("ed25519IsDeterministic", () => {
    const kp = generateKeyPair();
    expect(sign(kp.privateKey, utf8("m"))).toEqual(sign(kp.privateKey, utf8("m")));
  });
  it("keyPairMatchesOnlyItsOwnPair", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(keyPairMatches(a.privateKey, a.publicKey)).toBe(true);
    expect(keyPairMatches(a.privateKey, b.publicKey)).toBe(false);
  });
  it("keyPairMatchesFalseOnUnusableKeys", () => {
    const a = generateKeyPair();
    expect(keyPairMatches("not-a-key", a.publicKey)).toBe(false);
    expect(keyPairMatches(a.privateKey, "not-a-key")).toBe(false);
    expect(keyPairMatches(a.publicKey, a.publicKey)).toBe(false);
  });
  it("isEd25519PublicKeyAcceptsOnlyAnEd25519Spki", () => {
    const spki = (key: KeyObject): string => encode(key.export({ format: "der", type: "spki" }));
    const x25519 = spki(generateKeyPairSync("x25519").publicKey);
    const p256 = spki(generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey);
    expect(isEd25519PublicKey(generateKeyPair().publicKey)).toBe(true);
    expect(isEd25519PublicKey(x25519)).toBe(false);
    expect(isEd25519PublicKey(p256)).toBe(false);
    expect(isEd25519PublicKey(42)).toBe(false);
    expect(isEd25519PublicKey(undefined)).toBe(false);
    expect(isEd25519PublicKey("")).toBe(false);
    expect(isEd25519PublicKey("not base64url!")).toBe(false);
  });
});
