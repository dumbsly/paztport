// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { replacementRequest, sessionRequest } from "../../../mcp/src/index.ts";

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
