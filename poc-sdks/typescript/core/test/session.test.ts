// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../src/b64url.ts";
import { generateKeyPair, randomBytes, sign, utf8, verify } from "../src/crypto.ts";
import { canonicalize } from "../src/jcs.ts";
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
      sess: deriveSessionId(req.clientRoot?.sig ?? null, serverRoot.sig, req.nonce, serverNonce, req),
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
  const keys = { clientPolicyKey: "pk", clientKeyring: { session: "k" } };
  it("sessionIdDeterministic", () => {
    expect(deriveSessionId(a, b, n1, n2, keys)).toBe(deriveSessionId(a, b, n1, n2, keys));
  });
  it("sessionIdChangesWithEitherNonce", () => {
    const base = deriveSessionId(a, b, n1, n2, keys);
    expect(deriveSessionId(a, b, newNonce(), n2, keys)).not.toBe(base);
    expect(deriveSessionId(a, b, n1, newNonce(), keys)).not.toBe(base);
  });
  it("sessionIdChangesWithClientKeys", () => {
    const base = deriveSessionId(a, b, n1, n2, keys);
    expect(deriveSessionId(a, b, n1, n2, { ...keys, clientPolicyKey: "other" })).not.toBe(base);
    expect(deriveSessionId(a, b, n1, n2, { ...keys, clientKeyring: { session: "x" } })).not.toBe(base);
  });
  it("nullRootsNotInterchangeable", () => {
    expect(deriveSessionId(null, a, n1, n2, keys)).not.toBe(deriveSessionId(a, null, n1, n2, keys));
  });
  it("badLengthsThrow", () => {
    expect(() => deriveSessionId(encode(randomBytes(63)), b, n1, n2, keys)).toThrow();
    expect(() => deriveSessionId(a, encode(randomBytes(65)), n1, n2, keys)).toThrow();
    expect(() => deriveSessionId(a, b, encode(randomBytes(15)), n2, keys)).toThrow();
    expect(() => deriveSessionId(a, b, n1, encode(randomBytes(17)), keys)).toThrow();
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
  it("clientKeyringSwapFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, { ...w.req, clientKeyring: { session: "evil" } }, w.serverPolicy.publicKey)).toBe(false);
    expect(verifySessionReply(reply, { ...w.req, clientPolicyKey: generateKeyPair().publicKey }, w.serverPolicy.publicKey)).toBe(false);
  });
  it("attestedWithNullRootRejected", () => {
    const w = world();
    const noServer = signSessionReply({ ...w.body(), serverRoot: null, sess: deriveSessionId(w.clientRoot.sig, null, w.req.nonce, w.body().nonce, w.req) }, w.serverPolicy.privateKey);
    expect(verifySessionReply(noServer, w.req, w.serverPolicy.publicKey)).toBe(false);
    const body = w.body();
    const noClientReq = { ...w.req, clientRoot: null };
    const sess = deriveSessionId(null, w.serverRoot.sig, noClientReq.nonce, body.nonce, noClientReq);
    const reply = signSessionReply({ ...body, sess }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, noClientReq, w.serverPolicy.publicKey)).toBe(false);
  });
  it("nullServerRootReplyVerifies", () => {
    const w = world();
    const body = w.body();
    const sess = deriveSessionId(w.clientRoot.sig, null, w.req.nonce, body.nonce, w.req);
    const reply = signSessionReply({ ...body, serverRoot: null, sess, status: "unsafe" }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey)).toBe(true);
  });
  it("replyTamperedKeyringOrDisabledFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply({ ...reply, serverKeyring: { "mcp-entry": "evil" } }, w.req, w.serverPolicy.publicKey)).toBe(false);
    expect(verifySessionReply({ ...reply, disabled: ["x"] }, w.req, w.serverPolicy.publicKey)).toBe(false);
  });
  it("replyBadServerRootFails", () => {
    const w = world();
    const bad = { ...w.serverRoot, sig: encode(randomBytes(64)) };
    const reply = signSessionReply({ ...w.body(), serverRoot: bad }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey)).toBe(false);
  });
  it("replySignatureIsDomainSeparated", () => {
    const w = world();
    const body = w.body();
    const reply = signSessionReply(body, w.serverPolicy.privateKey);
    const prefixed = utf8("paztport-session-reply\n" + canonicalize(body));
    expect(verify(w.serverPolicy.publicKey, prefixed, decode(reply.sig))).toBe(true);
    // a signature over the bare canonical body (no domain prefix) is not accepted
    const bare = encode(sign(w.serverPolicy.privateKey, utf8(canonicalize(body))));
    expect(verifySessionReply({ ...reply, sig: bare }, w.req, w.serverPolicy.publicKey)).toBe(false);
  });
  it("signSessionReplyIgnoresStraySig", () => {
    const w = world();
    const body = w.body();
    const clean = signSessionReply(body, w.serverPolicy.privateKey);
    const stray = signSessionReply({ ...body, sig: "stray" } as Omit<SessionReply, "sig">, w.serverPolicy.privateKey);
    expect(stray.sig).not.toBe("stray");
    expect(stray).toEqual(clean); // Ed25519 is deterministic: same body, same signature
    expect(verifySessionReply(stray, w.req, w.serverPolicy.publicKey)).toBe(true);
  });
});
