// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/crypto.ts";
import { keyringSigningBytes, signKeyring, verifyKeyring } from "../src/keyring.ts";

describe("keyring", () => {
  it("signs the policy key and services under a domain prefix", () => {
    expect(Buffer.from(keyringSigningBytes("P", { a: "A" })).toString("utf8")).toBe('paztport-keyring\n{"policy":"P","services":{"a":"A"}}');
  });
  it("verifies only the signed services under the named policy key", () => {
    const p = generateKeyPair();
    const k = signKeyring({ a: "A" }, p.publicKey, p.privateKey);
    expect(verifyKeyring(k, p.publicKey)).toBe(true);
    expect(verifyKeyring({ ...k, services: { a: "B" } }, p.publicKey)).toBe(false);
    expect(verifyKeyring(k, generateKeyPair().publicKey)).toBe(false);
    expect(verifyKeyring({ ...k, sig: "!" }, p.publicKey)).toBe(false);
  });
});
