// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { signReplyCert } from "../../src/session/reply-cert.ts";
import { deriveSessionId, newNonce, signSessionReply, type SessionReply, type SessionRequest } from "../../src/session/session.ts";
import { checkSessionReply, serverPolicyNotAfter } from "../../src/session/reply-check.ts";

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
      serverReplyCert: signReplyCert(policy.publicKey, "mcp-entry", entry.publicKey, 30, policy.privateKey),
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

describe("checkSessionReply", () => {
  const T = 5;
  /** A request and the attested, entry-key-form reply that answers it. */
  function handshake(status: "attested" | "unsafe" = "attested") {
    const policy = generateKeyPair();
    const client = generateKeyPair();
    const entry = generateKeyPair();
    const { signedRoot } = buildPolicy([["mcp-entry", "github-tools"]], 8, policy.privateKey, 20);
    const clientRoot = buildPolicy([["pi", "mcp:github.t"]], 8, client.privateKey, 20).signedRoot;
    const ring = signKeyring({ "mcp-entry": entry.publicKey }, policy.publicKey, policy.privateKey, 10);
    const req: SessionRequest = {
      clientRoot,
      clientPolicyKey: client.publicKey,
      clientKeyring: {},
      clientKeyringSig: "x",
      nonce: newNonce(),
    };
    const serverNonce = newNonce();
    const sess = deriveSessionId(clientRoot.sig, signedRoot.sig, req.nonce, serverNonce, req);
    const reply = signSessionReply(
      {
        serverRoot: signedRoot,
        serverPolicyKey: policy.publicKey,
        serverKeyring: ring.services,
        serverKeyringSig: ring.sig,
        serverKeyringNotAfter: 10,
        serverReplyCert: signReplyCert(policy.publicKey, "mcp-entry", entry.publicKey, 30, policy.privateKey),
        nonce: serverNonce,
        sess,
        status,
        disabled: [],
      },
      entry.privateKey,
    );
    return { req, reply, pin: policy.publicKey };
  }
  const wire = (r: SessionReply): unknown => JSON.parse(JSON.stringify(r));
  it("namesEachOutcome", () => {
    const h = handshake();
    expect(checkSessionReply(wire(h.reply), h.req, h.pin, "mcp-entry", T)).toBe("ATTESTED");
    const u = handshake("unsafe");
    expect(checkSessionReply(wire(u.reply), u.req, u.pin, "mcp-entry", T)).toBe("UNSAFE");
    expect(checkSessionReply({ ...h.reply, disabled: "x" }, h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(null, h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(wire(h.reply), h.req, generateKeyPair().publicKey, "mcp-entry", T)).toBe("PIN_MISMATCH");
    expect(checkSessionReply(wire(h.reply), h.req, h.pin, "github-tools", T)).toBe("BAD_SIGNATURE");
    expect(checkSessionReply(wire({ ...h.reply, sess: "other" }), h.req, h.pin, "mcp-entry", T)).toBe("BAD_SIGNATURE");
  });
  it("judgesTheWindowsAtTheClientsClock", () => {
    const h = handshake();
    expect(checkSessionReply(wire(h.reply), h.req, h.pin, "mcp-entry", 10)).toBe("ATTESTED");
    expect(checkSessionReply(wire(h.reply), h.req, h.pin, "mcp-entry", 11)).toBe("BAD_SIGNATURE");
  });
  it("neverThrowsOnWhatTheWireCarries", () => {
    const h = handshake();
    for (const raw of [undefined, 1, "x", [], { serverRoot: 5 }, { ...h.reply, serverRoot: { rootId: 1 } }]) {
      expect(checkSessionReply(raw, h.req, h.pin, "mcp-entry", T), String(raw)).toBe("MALFORMED_REPLY");
    }
  });
});
