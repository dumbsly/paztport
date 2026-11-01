// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { concat, generateKeyPair, sign, utf8 } from "../../src/crypto/crypto.ts";
import { writeToken, writeWire } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
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
    // a reply the client's check refuses for a missing window fails every response check closed
    const { serverKeyringNotAfter: _k, ...noRingWindow } = r;
    expect(serverPolicyNotAfter(noRingWindow)).toBeNaN();
    // The policy-key form: its keyring is signed through the reply by the online policy key, so only the root is judged.
    const { serverKeyringSig: _s, serverReplyCert: _c, ...policyKeyForm } = r;
    expect(serverPolicyNotAfter(policyKeyForm)).toBe(20);
    expect(serverPolicyNotAfter({ ...policyKeyForm, serverRoot: null })).toBeNaN();
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
      clientKeyringNotAfter: 20,
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
    return { req, reply, pin: policy.publicKey, entry: entry.privateKey };
  }
  /** The reply's token, as the SDK writes it, with its members changed by `edit`. */
  const token = (r: object, edit: Record<string, unknown> = {}): string => writeToken({ ...r, ...edit } as JsonValue);
  /** `r` with `edit` applied and signed again by `key`, over every member it then has. */
  const resigned = (r: SessionReply, key: string, edit: Record<string, unknown>): string => {
    const { sig: _sig, ...body } = { ...r, ...edit };
    const signed = concat(utf8("paztport-session-reply\n"), writeWire(body as JsonValue));
    return token(body, { sig: encode(sign(key, signed)) });
  };
  it("namesEachOutcome", () => {
    const h = handshake();
    expect(checkSessionReply(token(h.reply), h.req, h.pin, "mcp-entry", T)).toBe("ATTESTED");
    const u = handshake("unsafe");
    expect(checkSessionReply(token(u.reply), u.req, u.pin, "mcp-entry", T)).toBe("UNSAFE");
    expect(checkSessionReply(token(h.reply, { disabled: "x" }), h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(token(h.reply, { serverKeyring: { "a/b": "k" } }), h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(writeToken(null), h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(token(h.reply), h.req, generateKeyPair().publicKey, "mcp-entry", T)).toBe("PIN_MISMATCH");
    expect(checkSessionReply(token(h.reply), h.req, h.pin, "github-tools", T)).toBe("BAD_SIGNATURE");
    expect(checkSessionReply(token(h.reply, { sess: "other" }), h.req, h.pin, "mcp-entry", T)).toBe("BAD_SIGNATURE");
  });
  it("judgesTheWindowsAtTheClientsClock", () => {
    const h = handshake();
    expect(checkSessionReply(token(h.reply), h.req, h.pin, "mcp-entry", 10)).toBe("ATTESTED");
    expect(checkSessionReply(token(h.reply), h.req, h.pin, "mcp-entry", 11)).toBe("BAD_SIGNATURE");
  });
  it("aReplyInWireMemberOrderIsMalformed", () => {
    const h = handshake();
    const text = new TextDecoder().decode(decode(token(h.reply)));
    const at = text.lastIndexOf(',"status":');
    const statusFirst = `{${text.slice(at + 1, -1)},${text.slice(1, at)}}`;
    expect(checkSessionReply(encode(utf8(text)), h.req, h.pin, "mcp-entry", T)).toBe("ATTESTED");
    expect(checkSessionReply(encode(utf8(statusFirst)), h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
    expect(checkSessionReply(encode(utf8(`${text}\n`)), h.req, h.pin, "mcp-entry", T)).toBe("MALFORMED_REPLY");
  });
  it("aReplyWithAnExtraMemberIsMalformed", () => {
    const h = handshake();
    const check = (edit: Record<string, unknown>) =>
      checkSessionReply(resigned(h.reply, h.entry, edit), h.req, h.pin, "mcp-entry", T);
    expect(check({})).toBe("ATTESTED");
    expect(check({ serverEntry: "mcp-entry" })).toBe("MALFORMED_REPLY");
    expect(check({ serverReplyCert: { ...h.reply.serverReplyCert!, note: "added" } })).toBe("MALFORMED_REPLY");
    expect(check({ serverRoot: { ...h.reply.serverRoot!, note: "added" } })).toBe("MALFORMED_REPLY");
  });
  it("neverThrowsOnWhatTheWireCarries", () => {
    const h = handshake();
    const shapes = [token({ serverRoot: 5 }), token(h.reply, { serverRoot: { rootId: 1 } })];
    for (const raw of [undefined, 1, "x", "not*base64url", writeToken([]), ...shapes]) {
      expect(checkSessionReply(raw as string, h.req, h.pin, "mcp-entry", T), String(raw)).toBe("MALFORMED_REPLY");
    }
  });
});
