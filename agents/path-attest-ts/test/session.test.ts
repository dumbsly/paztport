// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../src/b64url.ts";
import { generateKeyPair, randomBytes } from "../src/crypto.ts";
import { signRoot } from "../src/root.ts";
import {
  deriveSessionId,
  newNonce,
  sessionStatus,
  signSessionReply,
  verifySessionReply,
  type SessionReply,
  type SessionRequest,
} from "../src/session.ts";

function world() {
  const clientPolicy = generateKeyPair();
  const serverPolicy = generateKeyPair();
  const clientRoot = signRoot(randomBytes(32), "v1", clientPolicy.privateKey);
  const serverRoot = signRoot(randomBytes(32), "v2", serverPolicy.privateKey);
  const req: SessionRequest = {
    clientRoot,
    clientPolicyKey: clientPolicy.publicKey,
    clientKeyring: { session: "k" },
    nonce: newNonce(),
  };
  const body = (): Omit<SessionReply, "sig"> => {
    const serverNonce = newNonce();
    return {
      serverRoot,
      serverPolicyKey: serverPolicy.publicKey,
      serverKeyring: { "mcp-entry": "k2" },
      nonce: serverNonce,
      sess: deriveSessionId(req.clientRoot?.sig ?? null, serverRoot.sig, req.nonce, serverNonce),
      status: "attested",
      disabled: [],
    };
  };
  return { clientPolicy, serverPolicy, clientRoot, serverRoot, req, body };
}

describe("sessionStatus", () => {
  it("bothRootsAttested", () => {
    const w = world();
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey)).toBe("attested");
  });
  it("missingClientRootUnsafe", () => {
    const w = world();
    expect(sessionStatus({ ...w.req, clientRoot: null }, w.serverRoot, w.serverPolicy.publicKey)).toBe("unsafe");
  });
  it("clientRootBadSigUnsafe", () => {
    const w = world();
    const bad = { ...w.clientRoot, sig: encode(randomBytes(64)) };
    expect(sessionStatus({ ...w.req, clientRoot: bad }, w.serverRoot, w.serverPolicy.publicKey)).toBe("unsafe");
  });
  it("missingServerRootUnsafe", () => {
    const w = world();
    expect(sessionStatus(w.req, null, w.serverPolicy.publicKey)).toBe("unsafe");
  });
});

describe("deriveSessionId", () => {
  const a = encode(randomBytes(64));
  const b = encode(randomBytes(64));
  const n1 = newNonce();
  const n2 = newNonce();
  it("sessionIdDeterministic", () => {
    expect(deriveSessionId(a, b, n1, n2)).toBe(deriveSessionId(a, b, n1, n2));
    expect(deriveSessionId(null, null, n1, n2)).toBe(deriveSessionId("", "", n1, n2));
  });
  it("sessionIdChangesWithEitherNonce", () => {
    const base = deriveSessionId(a, b, n1, n2);
    expect(deriveSessionId(a, b, newNonce(), n2)).not.toBe(base);
    expect(deriveSessionId(a, b, n1, newNonce())).not.toBe(base);
  });
  it("nonceIs16Bytes", () => {
    expect(newNonce().length).toBe(22);
  });
});

describe("session reply", () => {
  it("replyVerifies", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey)).toBe(true);
  });
  it("replyTamperedStatusFails", () => {
    const w = world();
    const reply = signSessionReply({ ...w.body(), status: "unsafe" }, w.serverPolicy.privateKey);
    expect(verifySessionReply({ ...reply, status: "attested" }, w.req, w.serverPolicy.publicKey)).toBe(false);
  });
  it("replyWrongPinnedKeyFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, generateKeyPair().publicKey)).toBe(false);
  });
  it("replySessMismatchFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, { ...w.req, nonce: newNonce() }, w.serverPolicy.publicKey)).toBe(false);
  });
  it("replyBadServerRootFails", () => {
    const w = world();
    const bad = { ...w.serverRoot, sig: encode(randomBytes(64)) };
    const reply = signSessionReply({ ...w.body(), serverRoot: bad }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey)).toBe(false);
  });
});
