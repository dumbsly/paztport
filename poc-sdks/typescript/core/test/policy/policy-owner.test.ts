// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { signKeyring, signKeyringOldForm, verifyKeyring } from "../../src/policy/keyring.ts";
import type { SignedKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { issueReplyCert, renewKeyring, renewRoot } from "../../src/policy/policy-owner.ts";
import { signRoot, signRootOldForm, verifyRoot } from "../../src/policy/root.ts";
import { verifyReplyCert } from "../../src/session/reply-cert.ts";

const OLD = 1_000;
const NEW = 4_102_444_800_000;

const policy = generateKeyPair();
const other = generateKeyPair();

const services = () => ({ orders: generateKeyPair().publicKey });
const ring = (named: { publicKey: string }, signer: { publicKey: string; privateKey: string }, notAfter: number): SignedKeyring =>
  signKeyring(services(), named.publicKey, signer.privateKey, notAfter);

describe("policy owner", () => {
  it("renewsAKeyringInTheNewFormEvenWhenOldFormOrExpired", () => {
    const expired = ring(policy, policy, OLD);
    const oldForm = signKeyringOldForm(services(), policy.publicKey, policy.privateKey);
    for (const k of [expired, oldForm]) {
      const renewed = renewKeyring(k, NEW, policy.privateKey);
      expect(renewed.notAfter).toBe(NEW);
      expect(renewed.services).toEqual(k.services);
      expect(verifyKeyring(renewed, policy.publicKey)).toBe(true);
    }
  });

  it("refusesAKeyringThatDoesNotVerifyUnderTheKeyItNames", () => {
    const signed = ring(policy, policy, NEW);
    const tampered = { ...signed, services: services() };
    const { sig: _sig, ...unsigned } = signed;
    expect(() => renewKeyring(tampered, NEW, policy.privateKey)).toThrow("keyring is not signed by its policy key");
    expect(() => renewKeyring(unsigned as SignedKeyring, NEW, policy.privateKey)).toThrow("keyring is not signed by its policy key");
    expect(() => renewKeyring(ring(other, other, NEW), NEW, policy.privateKey)).toThrow("keyring is not signed by this policy key");
  });

  it("renewsARootOnlyIfThisKeySignedIt", () => {
    const built = buildPolicy([["gateway", "orders"]], 4, policy.privateKey, OLD).signedRoot;
    const renewed = renewRoot(built, policy.publicKey, NEW, policy.privateKey);
    expect(renewed.rootId).toBe(built.rootId);
    expect(renewed.root).toBe(built.root);
    expect(renewed.notAfter).toBe(NEW);
    expect(verifyRoot(renewed, policy.publicKey)).toBe(true);
    expect(() => renewRoot(built, other.publicKey, NEW, other.privateKey)).toThrow("root is not signed by this policy key");
  });

  it("renewsAnOldFormRootInTheNewForm", () => {
    const oldForm = signRootOldForm(new Uint8Array(32), "root-1", policy.privateKey);
    const renewed = renewRoot(oldForm, policy.publicKey, NEW, policy.privateKey);
    expect(renewed.notAfter).toBe(NEW);
    expect(renewed.rootId).toBe(oldForm.rootId);
    expect(renewed.root).toBe(oldForm.root);
    expect(verifyRoot(renewed, policy.publicKey)).toBe(true);
  });

  it("refusesToRenewARootWithAPrivateKeyThatIsNotThePolicyKeysOwn", () => {
    const root = signRoot(new Uint8Array(32), "root-1", policy.privateKey, OLD);
    expect(() => renewRoot(root, policy.publicKey, NEW, other.privateKey)).toThrow("root is not signed by this policy key");
  });

  it("refusesToRenewARootAgainstAMalformedPolicyKey", () => {
    const root = signRoot(new Uint8Array(32), "root-1", policy.privateKey, OLD);
    for (const key of [undefined, null, "", "not base64url!", encode(new Uint8Array(12))]) {
      expect(() => renewRoot(root, key as unknown as string, NEW, policy.privateKey), String(key)).toThrow(
        "root cannot be checked: the policy key is not an Ed25519 public key",
      );
    }
  });

  it("issuesAReplyCertOnlyForTheKeyTheKeyringHolds", () => {
    const k = ring(policy, policy, NEW);
    const cert = issueReplyCert(k, "orders", NEW, policy.privateKey);
    expect(cert.key).toBe(k.services.orders);
    expect(cert.svc).toBe("orders");
    expect(cert.notAfter).toBe(NEW);
    expect(verifyReplyCert(cert, policy.publicKey)).toBe(true);
    expect(() => issueReplyCert(k, "payment", NEW, policy.privateKey)).toThrow("keyring has no key for service payment");
    expect(() => issueReplyCert(k, "toString", NEW, policy.privateKey)).toThrow("keyring has no key for service toString");
  });

  it("refusesACertFromAKeyringThatDoesNotVerifyOrIsAnotherKeys", () => {
    const signed = ring(policy, policy, NEW);
    const tampered = { ...signed, services: services() };
    expect(() => issueReplyCert(tampered, "orders", NEW, policy.privateKey)).toThrow("keyring is not signed by its policy key");
    expect(() => issueReplyCert(ring(other, other, NEW), "orders", NEW, policy.privateKey)).toThrow("keyring is not signed by this policy key");
  });
});
