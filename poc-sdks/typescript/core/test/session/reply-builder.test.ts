// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { checkSessionReply } from "../../src/session/reply-check.ts";
import { sessionRequest } from "../../src/session/request.ts";
import { buildSessionReply, type ReplySource } from "../../src/session/reply-builder.ts";
import { signReplyCert } from "../../src/session/reply-cert.ts";
import { readSessionReply } from "../../src/session/session.ts";

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
    const reply = buildSessionReply(w.source, req, { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: ["w"], extensions: [] }, NOW);
    expect(reply.status).toBe("attested");
    expect(reply.disabled).toEqual([]);
    expect(reply.serverRoot).toEqual(w.source.signedRoot);
    expect(reply.serverKeyringNotAfter).toBe(FAR);
    expect(checkSessionReply(writeToken(reply), req, w.source.policyPublicKey, "mcp-entry", NOW)).toBe("ATTESTED");
  });
  it("opensAnUnsafeSessionListingTheDisabledToolsOtherwise", () => {
    const w = world();
    const req = w.req(null as never);
    for (const rules of [{ pinnedClientKeys: [], disabledWhenUnsafe: ["w", "x"], extensions: [] }, { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: ["w", "x"], extensions: [] }]) {
      const reply = buildSessionReply(w.source, req, rules, NOW);
      expect(reply.status).toBe("unsafe");
      expect(reply.disabled).toEqual(["w", "x"]);
      expect(checkSessionReply(writeToken(reply), req, w.source.policyPublicKey, "mcp-entry", NOW)).toBe("UNSAFE");
    }
  });
  it("listsTheRulesExtensionsSortedInEitherStatus", () => {
    const w = world();
    const none = { disabledWhenUnsafe: [], extensions: [] };
    const some = { disabledWhenUnsafe: [], extensions: ["influence", "example"] };
    const attested = [w.req(), [w.clientKey]] as const;
    const unsafe = [w.req(null as never), [w.clientKey]] as const;
    for (const [req, pinnedClientKeys] of [attested, unsafe]) {
      expect(buildSessionReply(w.source, req, { ...none, pinnedClientKeys }, NOW).extensions).toEqual([]);
      const reply = buildSessionReply(w.source, req, { ...some, pinnedClientKeys }, NOW);
      expect(reply.extensions).toEqual(["example", "influence"]);
      expect(readSessionReply(writeToken(reply)).extensions).toEqual(["example", "influence"]);
    }
    expect(buildSessionReply(w.source, attested[0], { ...some, pinnedClientKeys: [w.clientKey] }, NOW).status).toBe("attested");
    expect(buildSessionReply(w.source, unsafe[0], { ...some, pinnedClientKeys: [w.clientKey] }, NOW).status).toBe("unsafe");
  });
  it("drawsAFreshServerNonceEachTime", () => {
    const w = world();
    const req = w.req();
    const rules = { pinnedClientKeys: [w.clientKey], disabledWhenUnsafe: [], extensions: [] };
    const a = buildSessionReply(w.source, req, rules, NOW);
    const b = buildSessionReply(w.source, req, rules, NOW);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.sess).not.toBe(b.sess);
  });
});
