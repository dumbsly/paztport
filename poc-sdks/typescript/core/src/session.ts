// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { concat, randomBytes, sha256, sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";
import { verifyKeyring, type SignedKeyring } from "./keyring.ts";
import { isReplyCert, verifyReplyCert, type ReplyCert } from "./reply-cert.ts";
import { verifyRoot, type SignedRoot } from "./root.ts";
import { isCurrent, isNotAfter } from "./validity.ts";

/**
 * `clientKeyringSig` is the client policy key's signature over its keyring (see signKeyring), and
 * `clientKeyringNotAfter` that keyring's window, present exactly when the keyring is in the new form.
 */
export type SessionRequest = {
  clientRoot: SignedRoot | null;
  clientPolicyKey: string;
  clientKeyring: Record<string, string>;
  clientKeyringSig: string;
  clientKeyringNotAfter?: number;
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
 * `serverKeyringNotAfter` is the window `serverKeyringSig` was made over, present exactly when that keyring is in the new form.
 */
export type SessionReply = {
  serverRoot: SignedRoot | null;
  serverPolicyKey: string;
  serverKeyring: Record<string, string>;
  serverKeyringSig?: string;
  serverKeyringNotAfter?: number;
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

/**
 * The keyring a message presents, rebuilt whole: its window is the message's own `windowField` member when it has
 * one (an inherited one never counts), so a window moved, dropped or added in transit fails the signature.
 */
function presentedKeyring(msg: object, windowField: string, policy: string, services: Record<string, string>, sig: string): SignedKeyring {
  const ring: SignedKeyring = { policy, services, sig };
  return Object.hasOwn(msg, windowField) ? { ...ring, notAfter: (msg as Record<string, unknown>)[windowField] as number } : ring;
}

/** Whether the client's keyring signature verifies under its policy key, over `clientKeyringNotAfter` when the request has one. */
function keyringVerifies(req: SessionRequest): boolean {
  return verifyKeyring(presentedKeyring(req, "clientKeyringNotAfter", req.clientPolicyKey, req.clientKeyring, req.clientKeyringSig), req.clientPolicyKey);
}

/** True when `msg` has a valid window of its own in `field` and `at` is no later than it; an absent (old-form) or inherited one never counts. */
function windowCurrent(msg: object, field: string, at: number): boolean {
  if (!Object.hasOwn(msg, field)) return false;
  const n = (msg as Record<string, unknown>)[field];
  return isNotAfter(n) && at <= n;
}

/**
 * "attested" only when both roots verify against their sides' policy keys, the client's policy key is one the server
 * pinned, the client's keyring is signed by it, and at `now` (ms) the client's root and keyring and the server's own
 * root and keyring (`serverKeyringNotAfter`, undefined for an old-form keyring) are all new form and current. No pins
 * means every session is unsafe.
 *
 * Each signature is checked in its object's own form (a root over its own `notAfter`, the keyring over
 * `clientKeyringNotAfter`), so a window is judged only once the signature that covers it has verified: a client
 * window moved in transit fails that signature, and the root's own signature is the only guard on the root's.
 * The server's own windows are not re-verified here: they are the ones the server checked its keyring and root
 * against when it loaded them. A server whose own material has expired thus opens every new session unsafe and
 * keeps serving as it would an unattested caller, rather than stopping.
 */
export function sessionStatus(
  req: SessionRequest,
  serverRoot: SignedRoot | null,
  serverKeyringNotAfter: number | undefined,
  serverPolicyKey: string,
  pinnedClientKeys: readonly string[],
  now: number,
): "attested" | "unsafe" {
  return rootsVerify(req, serverRoot, serverPolicyKey) &&
    pinnedClientKeys.includes(req.clientPolicyKey) &&
    keyringVerifies(req) &&
    isCurrent(req.clientRoot!, now) &&
    windowCurrent(req, "clientKeyringNotAfter", now) &&
    isCurrent(serverRoot!, now) &&
    isNotAfter(serverKeyringNotAfter) &&
    now <= serverKeyringNotAfter
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
 * In the entry-key form `serverKeyringNotAfter` must be the window `serverKeyringSig` was made over, or the client's check fails.
 */
export function signSessionReply(reply: Omit<SessionReply, "sig">, signingPrivateKey: string): SessionReply {
  const { sig: _stray, ...body } = reply as Omit<SessionReply, "sig"> & { sig?: unknown };
  return { ...body, sig: encode(sign(signingPrivateKey, replySigningBytes(body))) };
}

/**
 * How a reply is judged: "live" by a client at its handshake, refusing a server root or keyring that is old form or
 * not current at `at`; "offline" for a recorded handshake, which accepts the old forms as recorded evidence holds
 * them and does not judge a new-form window.
 */
type ReplyMode = "live" | "offline";

/**
 * The key the reply's `sig` must verify under, or undefined when none may. The policy-key form (none of the
 * keyring-signature fields) names the pin; a `serverKeyringNotAfter` there is a keyring window with no keyring
 * signature, so no key. The entry-key form names the certified key of `serverEntry`, only if the keyring (over
 * `serverKeyringNotAfter` when the reply has one) and certificate verify under the pin, the certificate names
 * `serverEntry` and the keyring's key for it, `at` is no later than its `notAfter`, and, live, the keyring is new
 * form and current at `at`.
 */
function replySigner(reply: SessionReply, pin: string, serverEntry: string, at: number, mode: ReplyMode): string | undefined {
  const hasRingSig = Object.hasOwn(reply, "serverKeyringSig");
  const hasCert = Object.hasOwn(reply, "serverReplyCert");
  if (!hasRingSig && !hasCert) {
    return Object.hasOwn(reply, "serverKeyringNotAfter") ? undefined : pin;
  }
  const cert = reply.serverReplyCert;
  if (!hasRingSig || !hasCert || typeof reply.serverKeyringSig !== "string" || !isReplyCert(cert)) {
    return undefined;
  }
  const ring = reply.serverKeyring;
  const ok =
    verifyKeyring(presentedKeyring(reply, "serverKeyringNotAfter", reply.serverPolicyKey, ring, reply.serverKeyringSig), pin) &&
    verifyReplyCert(cert, pin) &&
    cert.svc === serverEntry &&
    Object.hasOwn(ring, serverEntry) &&
    ring[serverEntry] === cert.key &&
    typeof at === "number" &&
    at <= cert.notAfter &&
    (mode === "offline" || windowCurrent(reply, "serverKeyringNotAfter", at));
  return ok ? cert.key : undefined;
}

/**
 * The one reply check behind the live and offline verdicts (see ReplyMode): after the pin, `sig` under the key the
 * reply's form names (see replySigner), then the roots and the session id, the server root verifying under the pin
 * in its own form and, live, new form and current at `at`. A window is judged only after the signature over it has
 * verified (the root's under the pin, the keyring's in replySigner), so one moved in transit fails as a signature.
 * Never throws.
 */
function checkSessionReply(
  reply: SessionReply,
  req: SessionRequest | LegacySessionRequest,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
  mode: ReplyMode,
): boolean {
  try {
    if (reply.serverPolicyKey !== pinnedServerPolicyKey) {
      return false;
    }
    const signer = replySigner(reply, pinnedServerPolicyKey, serverEntry, at, mode);
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
    if (reply.serverRoot === null) {
      return true;
    }
    return verifyRoot(reply.serverRoot, pinnedServerPolicyKey) && (mode === "offline" || isCurrent(reply.serverRoot, at));
  } catch {
    return false;
  }
}

/**
 * The client's live check of a reply at time `at` (ms, its clock): checkSessionReply, refusing a server root, and in
 * the entry-key form a server keyring, that is old form or not current at `at`, in either status. `serverEntry` is
 * the client's own configuration, never the reply's. Never throws.
 */
export function verifySessionReply(
  reply: SessionReply,
  req: SessionRequest | LegacySessionRequest,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
): boolean {
  return checkSessionReply(reply, req, pinnedServerPolicyKey, serverEntry, at, "live");
}

/**
 * Whether a recorded handshake opened an attested session: the reply is attested and verifies against the
 * pin, and both roots verify against their sides' policy keys. The reply binds the client root's signature
 * but not its contents, so the client root is checked here too, and so is the keyring's signature unless
 * the request is legacy. There is no client pin offline: the server's signed "attested" reply, whose
 * session id binds the client's policy key and keyring, is its statement that it pinned them. `at` is the time
 * of the record judged (a call's recorded time), since the handshake record carries no signed time: an entry-key
 * reply is attested only for records no later than its certificate's `notAfter`. Policy-key replies ignore it.
 * The reply is checked offline (see ReplyMode): old-form roots and keyrings are accepted, as recorded evidence holds
 * them, and new-form windows are not judged. Never throws.
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
      checkSessionReply(reply, req, pinnedServerPolicyKey, serverEntry, at, "offline") &&
      rootsVerify(req, reply.serverRoot, reply.serverPolicyKey) &&
      (isLegacySessionRequest(req) || keyringVerifies(req))
    );
  } catch {
    return false;
  }
}
