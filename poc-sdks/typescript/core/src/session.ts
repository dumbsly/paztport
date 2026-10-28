// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { concat, randomBytes, sha256, sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";
import { verifyKeyring } from "./keyring.ts";
import { isReplyCert, verifyReplyCert, type ReplyCert } from "./reply-cert.ts";
import { verifyRoot, type SignedRoot } from "./root.ts";

/** `clientKeyringSig` is the client policy key's signature over its keyring (see signKeyring). */
export type SessionRequest = {
  clientRoot: SignedRoot | null;
  clientPolicyKey: string;
  clientKeyring: Record<string, string>;
  clientKeyringSig: string;
  nonce: string;
};

/** A request from before keyrings were signed: it carries no `clientKeyringSig`. */
export type LegacySessionRequest = Omit<SessionRequest, "clientKeyringSig">;

/**
 * True when the request has no `clientKeyringSig` field, as a recorded request from before signed keyrings
 * does. A field that is present but not a string is a v3 request whose signature fails, not a legacy one.
 */
export function isLegacySessionRequest(req: SessionRequest | LegacySessionRequest): req is LegacySessionRequest {
  return !Object.hasOwn(req, "clientKeyringSig");
}

/**
 * A reply carrying `serverKeyringSig` and `serverReplyCert` is signed by the entry service's certified key; one
 * with neither is signed by the server policy key. Which form it is depends only on which fields are present.
 */
export type SessionReply = {
  serverRoot: SignedRoot | null;
  serverPolicyKey: string;
  serverKeyring: Record<string, string>;
  serverKeyringSig?: string;
  serverReplyCert?: ReplyCert;
  nonce: string;
  sess: string;
  status: "attested" | "unsafe";
  disabled: string[];
  sig: string;
};

export function newNonce(): string {
  return encode(randomBytes(16));
}

export type ClientKeys = { clientPolicyKey: string; clientKeyring: Record<string, string> };

function fixed(value: string, length: number, what: string): Uint8Array {
  const bytes = decode(value);
  if (bytes.length !== length) {
    throw new Error(`${what} must be ${length} bytes`);
  }
  return bytes;
}

/** Binds both roots, both nonces and the client's policy key and keyring; throws on bad lengths. */
export function deriveSessionId(
  clientRootSig: string | null,
  serverRootSig: string | null,
  clientNonce: string,
  serverNonce: string,
  clientKeys: ClientKeys,
): string {
  const flags = (clientRootSig !== null ? 1 : 0) | (serverRootSig !== null ? 2 : 0);
  const keysHash = sha256(utf8(canonicalize({ clientPolicyKey: clientKeys.clientPolicyKey, clientKeyring: clientKeys.clientKeyring })));
  return encode(
    sha256(
      concat(
        new Uint8Array([0x02, flags]),
        clientRootSig === null ? new Uint8Array(0) : fixed(clientRootSig, 64, "clientRootSig"),
        serverRootSig === null ? new Uint8Array(0) : fixed(serverRootSig, 64, "serverRootSig"),
        fixed(clientNonce, 16, "clientNonce"),
        fixed(serverNonce, 16, "serverNonce"),
        keysHash,
      ),
    ),
  );
}

/** Whether both roots are present and each verifies against its side's policy key. */
function rootsVerify(req: SessionRequest | LegacySessionRequest, serverRoot: SignedRoot | null, serverPolicyKey: string): boolean {
  return req.clientRoot !== null && serverRoot !== null && verifyRoot(req.clientRoot, req.clientPolicyKey) && verifyRoot(serverRoot, serverPolicyKey);
}

function keyringVerifies(req: SessionRequest): boolean {
  return verifyKeyring({ policy: req.clientPolicyKey, services: req.clientKeyring, sig: req.clientKeyringSig }, req.clientPolicyKey);
}

/**
 * "attested" only when both roots verify against their sides' policy keys, the client's policy key is
 * one the server pinned, and the client's keyring is signed by it. No pins means every session is unsafe.
 */
export function sessionStatus(
  req: SessionRequest,
  serverRoot: SignedRoot | null,
  serverPolicyKey: string,
  pinnedClientKeys: readonly string[],
): "attested" | "unsafe" {
  return rootsVerify(req, serverRoot, serverPolicyKey) && pinnedClientKeys.includes(req.clientPolicyKey) && keyringVerifies(req)
    ? "attested"
    : "unsafe";
}

/** The bytes a session reply signature covers: domain prefix + JCS of the reply without "sig". */
function replySigningBytes(body: Omit<SessionReply, "sig">): Uint8Array {
  return utf8("paztport-session-reply\n" + canonicalize(body));
}

/**
 * Signs the reply with the entry service's key (the entry-key form) or the policy key (the policy-key form); any
 * "sig" on the input is dropped first. Only the key changed: the server says "attested" only after its status checks.
 */
export function signSessionReply(reply: Omit<SessionReply, "sig">, signingPrivateKey: string): SessionReply {
  const { sig: _stray, ...body } = reply as Omit<SessionReply, "sig"> & { sig?: unknown };
  return { ...body, sig: encode(sign(signingPrivateKey, replySigningBytes(body))) };
}

/**
 * The key the reply's `sig` must verify under, or undefined when none may: the pin for the policy-key form; for the
 * entry-key form, the certified key of `serverEntry`, only if the keyring and certificate verify under the pin, the
 * certificate names `serverEntry` and the keyring's key for it, and `at` is no later than its `notAfter`.
 */
function replySigner(reply: SessionReply, pin: string, serverEntry: string, at: number): string | undefined {
  const hasRingSig = Object.hasOwn(reply, "serverKeyringSig");
  const hasCert = Object.hasOwn(reply, "serverReplyCert");
  if (!hasRingSig && !hasCert) {
    return pin;
  }
  const cert = reply.serverReplyCert;
  if (!hasRingSig || !hasCert || typeof reply.serverKeyringSig !== "string" || !isReplyCert(cert)) {
    return undefined;
  }
  const ring = reply.serverKeyring;
  const ok =
    verifyKeyring({ policy: reply.serverPolicyKey, services: ring, sig: reply.serverKeyringSig }, pin) &&
    verifyReplyCert(cert, pin) &&
    cert.svc === serverEntry &&
    Object.hasOwn(ring, serverEntry) &&
    ring[serverEntry] === cert.key &&
    typeof at === "number" &&
    at <= cert.notAfter;
  return ok ? cert.key : undefined;
}

/**
 * The client's check of a reply at time `at` (ms), after the pin: `sig` under the key the reply's form names
 * (see replySigner), then the roots and the session id. `serverEntry` is the client's own configuration, never
 * the reply's. Never throws.
 */
export function verifySessionReply(
  reply: SessionReply,
  req: SessionRequest | LegacySessionRequest,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
): boolean {
  try {
    if (reply.serverPolicyKey !== pinnedServerPolicyKey) {
      return false;
    }
    const signer = replySigner(reply, pinnedServerPolicyKey, serverEntry, at);
    const { sig, ...body } = reply;
    if (signer === undefined || !verify(signer, replySigningBytes(body), decode(sig))) {
      return false;
    }
    if (reply.status === "attested" && (reply.serverRoot === null || req.clientRoot === null)) {
      return false;
    }
    const expected = deriveSessionId(req.clientRoot?.sig ?? null, reply.serverRoot?.sig ?? null, req.nonce, reply.nonce, req);
    if (reply.sess !== expected) {
      return false;
    }
    return reply.serverRoot === null || verifyRoot(reply.serverRoot, pinnedServerPolicyKey);
  } catch {
    return false;
  }
}

/**
 * Whether a recorded handshake opened an attested session: the reply is attested and verifies against the
 * pin, and both roots verify against their sides' policy keys. The reply binds the client root's signature
 * but not its contents, so the client root is checked here too, and so is the keyring's signature unless
 * the request is legacy. There is no client pin offline: the server's signed "attested" reply, whose
 * session id binds the client's policy key and keyring, is its statement that it pinned them. `at` is the time
 * of the record judged (a call's recorded time), since the handshake record carries no signed time: an entry-key
 * reply is attested only for records no later than its certificate's `notAfter`. Policy-key replies ignore it.
 * Never throws.
 */
export function isAttestedSession(
  req: SessionRequest | LegacySessionRequest,
  reply: SessionReply,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
): boolean {
  try {
    return (
      reply.status === "attested" &&
      verifySessionReply(reply, req, pinnedServerPolicyKey, serverEntry, at) &&
      rootsVerify(req, reply.serverRoot, reply.serverPolicyKey) &&
      (isLegacySessionRequest(req) || keyringVerifies(req))
    );
  } catch {
    return false;
  }
}
