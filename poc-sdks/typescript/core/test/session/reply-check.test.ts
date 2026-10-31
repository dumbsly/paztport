// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { issueReplyCert } from "../../src/session/reply-cert.ts";
import { signSessionReply, type SessionReply } from "../../src/session/session.ts";
import { serverPolicyNotAfter } from "../../../mcp/src/index.ts";

/** An entry-key-form reply whose root window is 20 and keyring window 10. */
function reply(): SessionReply {
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const { signedRoot } = buildPolicy([["mcp-entry", "github-tools"]], 8, policy.privateKey, 20);
  const ring = signKeyring({ "mcp-entry": entry.publicKey }, policy.publicKey, policy.privateKey, 10);
  return signSessionReply(
    {
      serverRoot: signedRoot,
      serverPolicyKey: policy.publicKey,
      serverKeyring: ring.services,
      serverKeyringSig: ring.sig,
      serverKeyringNotAfter: 10,
      serverReplyCert: issueReplyCert(policy.publicKey, "mcp-entry", entry.publicKey, 30, policy.privateKey),
      nonce: "n",
      sess: "s",
      status: "attested",
      disabled: [],
    },
    entry.privateKey,
  );
}

describe("serverPolicyNotAfter", () => {
  it("countsTheKeyringOnlyInTheEntryKeyForm", () => {
    const r = reply();
    expect(Object.hasOwn(r, "serverKeyringSig")).toBe(true);
    expect(serverPolicyNotAfter(r)).toBe(10);
    expect(serverPolicyNotAfter({ ...r, serverKeyringNotAfter: 30 })).toBe(20);
    const { serverKeyringNotAfter: _k, ...oldRing } = r;
    expect(serverPolicyNotAfter(oldRing), "an old-form keyring in the entry-key form").toBeUndefined();
    // The policy-key form: its keyring is signed through the reply by the online policy key, so only the root is judged.
    const { serverKeyringSig: _s, serverReplyCert: _c, ...policyKeyForm } = r;
    expect(serverPolicyNotAfter(policyKeyForm)).toBe(20);
    expect(serverPolicyNotAfter({ ...policyKeyForm, serverRoot: null })).toBeUndefined();
  });
});
