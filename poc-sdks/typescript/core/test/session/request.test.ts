// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { isLegacySessionRequest, type SessionRequest } from "../../src/session/session.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { parseSessionRequest, replacementRequest, sessionRequest } from "../../src/session/request.ts";

/** Valid until 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

function clientMaterial() {
  const policy = generateKeyPair();
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const { signedRoot } = buildPolicy([["session", "pi", "mcp:github.list_issues"]], 8, policy.privateKey, NOT_AFTER);
  const ring = signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey, NOT_AFTER);
  return { signedRoot, policyPublicKey: policy.publicKey, keyring: ring.services, keyringSig: ring.sig, keyringNotAfter: ring.notAfter };
}

describe("sessionRequest", () => {
  it("carriesTheClientsRootKeysAndAFreshNonce", () => {
    const client = clientMaterial();
    const a = sessionRequest(client);
    const b = sessionRequest({ ...client, signedRoot: null });
    expect(Object.keys(a)).toEqual(["clientRoot", "clientPolicyKey", "clientKeyring", "clientKeyringSig", "clientKeyringNotAfter", "nonce"]);
    expect(a).toMatchObject({
      clientRoot: client.signedRoot,
      clientPolicyKey: client.policyPublicKey,
      clientKeyring: client.keyring,
      clientKeyringSig: client.keyringSig,
      clientKeyringNotAfter: NOT_AFTER,
    });
    expect(a.clientRoot!.notAfter).toBe(NOT_AFTER);
    expect(b.clientRoot).toBeNull();
    expect(a.nonce).not.toBe(b.nonce);
  });
  it("carriesTheKeyringWindowOnlyForANewFormKeyring", () => {
    const { keyringNotAfter: _w, ...old } = clientMaterial();
    const req = sessionRequest(old);
    expect(Object.keys(req)).toEqual(["clientRoot", "clientPolicyKey", "clientKeyring", "clientKeyringSig", "nonce"]);
    expect(Object.keys(sessionRequest({ ...old, keyringNotAfter: undefined }))).not.toContain("clientKeyringNotAfter");
  });
});

describe("replacementRequest", () => {
  it("dropsTheRootWithAFreshNonce", () => {
    const req = sessionRequest(clientMaterial());
    const r = replacementRequest(req);
    expect(Object.keys(r)).toEqual(Object.keys(req));
    expect(r).toEqual({ ...req, clientRoot: null, nonce: r.nonce });
    expect(r.nonce).not.toBe(req.nonce);
  });
});

describe("parseSessionRequest", () => {
  const wire = () => JSON.parse(JSON.stringify(sessionRequest(clientMaterial()))) as Record<string, unknown>;
  it("readsWhatSessionRequestWrites", () => {
    const req = sessionRequest(clientMaterial());
    expect(parseSessionRequest(JSON.parse(JSON.stringify(req)))).toEqual(req);
  });
  it("readsAMissingKeyringSignatureAsAbsentAndANonStringOneAsEmpty", () => {
    const { clientKeyringSig: _sig, ...legacy } = wire();
    const parsed = parseSessionRequest(legacy);
    expect(Object.hasOwn(parsed, "clientKeyringSig")).toBe(false);
    expect(isLegacySessionRequest(parsed)).toBe(true);
    for (const bad of [null, 7, ["x"], {}]) {
      expect((parseSessionRequest({ ...legacy, clientKeyringSig: bad }) as SessionRequest).clientKeyringSig).toBe("");
    }
  });
  it("keepsTheClientRootWholeAndTheKeyringWindow", () => {
    const req = sessionRequest(clientMaterial());
    const parsed = parseSessionRequest(JSON.parse(JSON.stringify(req)));
    expect(parsed.clientRoot).toEqual(req.clientRoot);
    expect(parsed.clientKeyringNotAfter).toBe(NOT_AFTER);
  });
  it("namesTheBadField", () => {
    expect(() => parseSessionRequest(null)).toThrow("session request must be an object");
    expect(() => parseSessionRequest([])).toThrow("session request must be an object");
    expect(() => parseSessionRequest({ ...wire(), clientRoot: "x" })).toThrow("clientRoot must be an object or null");
    expect(() => parseSessionRequest({ ...wire(), clientKeyring: [] })).toThrow("clientKeyring must be an object");
    expect(() => parseSessionRequest({ ...wire(), clientKeyring: { a: 1 } })).toThrow("clientKeyring entry a must be a string");
    expect(() => parseSessionRequest({ ...wire(), clientPolicyKey: 1 })).toThrow("clientPolicyKey must be a string");
    expect(() => parseSessionRequest({ ...wire(), nonce: undefined })).toThrow("nonce must be a string");
    for (const bad of [null, -1, 1.5, "7", 2 ** 53]) {
      expect(() => parseSessionRequest({ ...wire(), clientKeyringNotAfter: bad }), String(bad)).toThrow("clientKeyringNotAfter");
    }
  });
  it("keepsAnInheritedNameAsAnOrdinaryKey", () => {
    const text = JSON.stringify(wire()).replace('"clientKeyring":{', '"clientKeyring":{"__proto__":"k",');
    const parsed = parseSessionRequest(JSON.parse(text));
    expect(Object.hasOwn(parsed.clientKeyring, "__proto__")).toBe(true);
  });
});
