// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, randomBytes, sha256, sign, utf8, verify } from "../crypto/crypto.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { array, exactly, int, object, str, stringMap } from "../internal/fields.ts";
import { verifyKeyring, type SignedKeyring } from "../policy/keyring.ts";
import { replyCertOf, verifyReplyCert, type ReplyCert } from "./reply-cert.ts";
import { rootOf, verifyRoot, type SignedRoot } from "../policy/root.ts";
import { isCurrent, isNotAfter } from "../policy/validity.ts";

/**
 * `clientKeyringSig` is the client policy key's signature over its keyring (see signKeyring), and
 * `clientKeyringNotAfter` that keyring's window.
 */
export type SessionRequest = {
  clientRoot: SignedRoot | null;
  clientPolicyKey: string;
  clientKeyring: Record<string, string>;
  clientKeyringSig: string;
  clientKeyringNotAfter: number;
  nonce: string;
};

/**
 * A reply carrying `serverKeyringSig` and `serverReplyCert` is signed by the entry service's certified key; one
 * with neither is signed by the server policy key. Which form it is depends only on which fields are present.
 * `serverKeyringNotAfter` is the window `serverKeyringSig` was made over, present exactly when `serverKeyringSig` is.
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

/**
 * Reads a reply from its token: MalformedJson for bytes that are not exactly the canonical bytes of one value, and an
 * Error naming the member for a reply other than exactly its members: `serverRoot` null or a root with exactly its
 * own members, string `serverPolicyKey`, `nonce`, `sess` and `sig`, a `serverKeyring` of strings, `status`
 * "attested" or "unsafe", a `disabled` array of strings, and, each only when present, a string `serverKeyringSig`,
 * which needs `serverKeyringNotAfter` beside it, an integer `serverKeyringNotAfter`, and a `serverReplyCert` with
 * exactly a certificate's members. A member whose value is null is present. Checks no signature.
 */
export function readSessionReply(token: string): SessionReply {
  const o = object(readToken(token));
  exactly(o, ["disabled", "nonce", "serverKeyring", "serverPolicyKey", "serverRoot", "sess", "sig", "status"], [
    "serverKeyringNotAfter",
    "serverKeyringSig",
    "serverReplyCert",
  ]);
  const status = str(o, "status");
  if (status !== "attested" && status !== "unsafe") throw new Error("member status is neither attested nor unsafe");
  const disabled = array(o, "disabled").map((d) => {
    if (typeof d !== "string") throw new Error("member disabled holds a value that is not a string");
    return d;
  });
  const reply: SessionReply = {
    serverRoot: o.serverRoot === null ? null : rootOf(o.serverRoot!),
    serverPolicyKey: str(o, "serverPolicyKey"),
    serverKeyring: stringMap(o, "serverKeyring"),
    nonce: str(o, "nonce"),
    sess: str(o, "sess"),
    status,
    disabled,
    sig: str(o, "sig"),
  };
  if (Object.hasOwn(o, "serverKeyringSig")) {
    reply.serverKeyringSig = str(o, "serverKeyringSig");
    if (!Object.hasOwn(o, "serverKeyringNotAfter")) throw new Error("no member serverKeyringNotAfter");
  }
  if (Object.hasOwn(o, "serverKeyringNotAfter")) reply.serverKeyringNotAfter = int(o, "serverKeyringNotAfter");
  if (Object.hasOwn(o, "serverReplyCert")) reply.serverReplyCert = replyCertOf(o.serverReplyCert!);
  return reply;
}

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
  // The client's keys as one Paztport object, hashed over its canonical bytes.
  const { clientPolicyKey, clientKeyring } = clientKeys;
  const keysHash = sha256(writeWire({ clientPolicyKey, clientKeyring }));
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
function rootsVerify(req: SessionRequest, serverRoot: SignedRoot | null, serverPolicyKey: string): boolean {
  return req.clientRoot !== null && serverRoot !== null && verifyRoot(req.clientRoot, req.clientPolicyKey) && verifyRoot(serverRoot, serverPolicyKey);
}

/**
 * The keyring a message presents, rebuilt whole: its window is the message's own `windowField` member (an inherited
 * one never counts, and a missing one fails), so a window moved in transit fails the signature.
 */
function presentedKeyring(msg: object, windowField: string, policy: string, services: Record<string, string>, sig: string): SignedKeyring {
  const ring = { policy, services, sig };
  return (Object.hasOwn(msg, windowField) ? { ...ring, notAfter: (msg as Record<string, unknown>)[windowField] } : ring) as SignedKeyring;
}

/** Whether the client's keyring signature verifies under its policy key, over `clientKeyringNotAfter`. */
function keyringVerifies(req: SessionRequest): boolean {
  const { clientPolicyKey, clientKeyring, clientKeyringSig } = req;
  return verifyKeyring(presentedKeyring(req, "clientKeyringNotAfter", clientPolicyKey, clientKeyring, clientKeyringSig), clientPolicyKey);
}

/** True when `msg` has a valid window of its own in `field` and `at` is no later than it; a missing or inherited one never counts. */
function windowCurrent(msg: object, field: string, at: number): boolean {
  if (!Object.hasOwn(msg, field)) return false;
  const n = (msg as Record<string, unknown>)[field];
  return isNotAfter(n) && at <= n;
}

/**
 * "attested" only when both roots verify against their sides' policy keys, the client's policy key is one the server
 * pinned, the client's keyring is signed by it, and at `now` (ms) the client's root and keyring and the server's own
 * root and keyring (`serverKeyringNotAfter`) are all current. No pins means every session is unsafe.
 *
 * Each signature is checked over its object's window (a root over its own `notAfter`, the keyring over
 * `clientKeyringNotAfter`), so a window is judged only once the signature that covers it has verified: a client
 * window moved in transit fails that signature, and the root's own signature is the only guard on the root's.
 * The server's own windows are not re-verified here: they are the ones the server checked its keyring and root
 * against when it loaded them. A server whose own material has expired thus opens every new session unsafe and
 * keeps serving as it would an unattested caller, rather than stopping.
 */
export function sessionStatus(
  req: SessionRequest,
  serverRoot: SignedRoot | null,
  serverKeyringNotAfter: number,
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
  return concat(utf8("paztport-session-reply\n"), writeWire(body as JsonValue));
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
 * The key the reply's `sig` must verify under, or undefined when none may. The policy-key form (none of the
 * keyring-signature fields) names the pin; a `serverKeyringNotAfter` there is a keyring window with no keyring
 * signature, so no key. The entry-key form names the certified key of `serverEntry`, only if the keyring (over
 * `serverKeyringNotAfter`) and certificate verify under the pin, the certificate names `serverEntry` and the
 * keyring's key for it, `at` is no later than its `notAfter`, and the keyring is current at `at`.
 */
function replySigner(reply: SessionReply, pin: string, serverEntry: string, at: number): string | undefined {
  const hasRingSig = Object.hasOwn(reply, "serverKeyringSig");
  const hasCert = Object.hasOwn(reply, "serverReplyCert");
  if (!hasRingSig && !hasCert) {
    return Object.hasOwn(reply, "serverKeyringNotAfter") ? undefined : pin;
  }
  const cert = reply.serverReplyCert;
  if (!hasRingSig || !hasCert || typeof reply.serverKeyringSig !== "string" || cert === undefined) {
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
    windowCurrent(reply, "serverKeyringNotAfter", at);
  return ok ? cert.key : undefined;
}

/**
 * The one reply check behind the live and offline verdicts, judged at `at`, the client's clock live and the time of
 * the record judged offline: after the pin, `sig` under the key the reply's form names (see replySigner), then the
 * roots and the session id, the server root verifying under the pin over its own `notAfter` and current at `at`. A
 * window is judged only after the signature over it has verified (the root's under the pin, the keyring's in
 * replySigner), so one moved in transit fails as a signature. Never throws.
 */
function replyHolds(reply: SessionReply, req: SessionRequest, pinnedServerPolicyKey: string, serverEntry: string, at: number): boolean {
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
    if (reply.serverRoot === null) {
      return true;
    }
    return verifyRoot(reply.serverRoot, pinnedServerPolicyKey) && isCurrent(reply.serverRoot, at);
  } catch {
    return false;
  }
}

/**
 * The client's live check of a reply at time `at` (ms, its clock): replyHolds, refusing a server root, and in
 * the entry-key form a server keyring, that is not current at `at`, in either status. `serverEntry` is
 * the client's own configuration, never the reply's. Never throws.
 */
export function verifySessionReply(
  reply: SessionReply,
  req: SessionRequest,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
): boolean {
  return replyHolds(reply, req, pinnedServerPolicyKey, serverEntry, at);
}

/**
 * Whether a recorded handshake opened an attested session: the reply's token reads (readSessionReply, as
 * checkSessionReply reads it first), the reply is attested and verifies against the pin, and both roots verify
 * against their sides' policy keys. The reply binds the client root's signature
 * but not its contents, so the client root is checked here too, and so is the keyring's signature.
 * There is no client pin offline: the server's signed "attested" reply, whose
 * session id binds the client's policy key and keyring, is its statement that it pinned them. `at` is the time
 * of the record judged, since the handshake record carries no signed time: the caller passes a time the client signed
 * (a call's last stamp `ts`). The session is attested only for records no later than its certificate's `notAfter`
 * (entry-key form) and the `notAfter` of each root and keyring, on both sides, each read only after its own
 * signature verified. The caller must not take `at` from the handshake record, which anyone holding the file can
 * edit. Never throws.
 */
export function isAttestedSession(
  req: SessionRequest,
  replyToken: string,
  pinnedServerPolicyKey: string,
  serverEntry: string,
  at: number,
): boolean {
  try {
    const reply = readSessionReply(replyToken);
    return (
      reply.status === "attested" &&
      replyHolds(reply, req, pinnedServerPolicyKey, serverEntry, at) &&
      rootsVerify(req, reply.serverRoot, reply.serverPolicyKey) &&
      keyringVerifies(req) &&
      isCurrent(req.clientRoot!, at) &&
      windowCurrent(req, "clientKeyringNotAfter", at)
    );
  } catch {
    return false;
  }
}
