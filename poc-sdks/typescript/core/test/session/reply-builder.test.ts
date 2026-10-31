// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { checkSessionReply } from "../../src/session/reply-check.ts";
import { sessionRequest } from "../../src/session/request.ts";
import { buildSessionReply, type ReplySource } from "../../src/session/reply-builder.ts";
import { signReplyCert } from "../../src/session/reply-cert.ts";

const FAR = 4_102_444_800_000;
const NOW = 1_767_225_600_000;

function world() {
  const serverPolicy = generateKeyPair();
  const clientPolicy = generateKeyPair();
  const entry = generateKeyPair();
  const { signedRoot } = buildPolicy([["mcp-entry", "tools"]], 8, serverPolicy.privateKey, FAR);
  const ring = signKeyring({ "mcp-entry": entry.publicKey }, serverPolicy.publicKey, serverPolicy.privateKey, FAR);
  const source: ReplySource = {
    signedRoot,
    policyPublicKey: serverPolicy.publicKey,
    keyring: ring.services,
    keyringSig: ring.sig,
    keyringNotAfter: FAR,
    replyCert: signReplyCert(serverPolicy.publicKey, "mcp-entry", entry.publicKey, FAR, serverPolicy.privateKey),
    entryPrivateKey: entry.privateKey,
  };
  const clientRoot = buildPolicy([["pi", "mcp:s.t"]], 8, clientPolicy.privateKey, FAR).signedRoot;
  const cring = signKeyring({ pi: generateKeyPair().publicKey }, clientPolicy.publicKey, clientPolicy.privateKey, FAR);
  const req = (root = clientRoot) =>
    sessionRequest({ signedRoot: root, policyPublicKey: clientPolicy.publicKey, keyring: cring.services, keyringSig: cring.sig, keyringNotAfter: FAR });
  return { source, req, clientKey: clientPolicy.publicKey };
}

describe("buildSessionReply", () => {
  it("attestsAPinnedClientWithBothRootsAndSignsAsTheEntry", () => {
    const w = world();
    const req = w.req();
    const reply = buildSessionReply(w.source, req, { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: ["w"] }, NOW);
    expect(reply.status).toBe("attested");
    expect(reply.disabled).toEqual([]);
    expect(reply.serverRoot).toEqual(w.source.signedRoot);
    expect(reply.serverKeyringNotAfter).toBe(FAR);
    expect(checkSessionReply(JSON.parse(JSON.stringify(reply)), req, w.source.policyPublicKey, "mcp-entry", NOW)).toBe("ATTESTED");
  });
  it("opensAnUnsafeSessionListingTheDisabledToolsOtherwise", () => {
    const w = world();
    const req = w.req(null as never);
    for (const rules of [{ pinnedClientKeys: [], disabledWhenUnsafe: ["w", "x"] }, { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: ["w", "x"] }]) {
      const reply = buildSessionReply(w.source, req, rules, NOW);
      expect(reply.status).toBe("unsafe");
      expect(reply.disabled).toEqual(["w", "x"]);
      expect(checkSessionReply(JSON.parse(JSON.stringify(reply)), req, w.source.policyPublicKey, "mcp-entry", NOW)).toBe("UNSAFE");
    }
  });
  it("drawsAFreshServerNonceEachTime", () => {
    const w = world();
    const req = w.req();
    const rules = { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: [] };
    const a = buildSessionReply(w.source, req, rules, NOW);
    const b = buildSessionReply(w.source, req, rules, NOW);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.sess).not.toBe(b.sess);
  });
});
