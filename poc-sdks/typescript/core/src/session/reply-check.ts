// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { earliestNotAfter, isNotAfter } from "../policy/validity.ts";
import { parseSignedRoot } from "../policy/root.ts";
import { isReplyCert } from "./reply-cert.ts";
import { verifySessionReply, type SessionReply, type SessionRequest } from "./session.ts";

/** What a client concludes from a handshake reply: the vocabulary of the spec's session-reply vectors. */
export type ReplyCheck = "ATTESTED" | "UNSAFE" | "MALFORMED_REPLY" | "PIN_MISMATCH" | "BAD_SIGNATURE";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isStringMap(v: unknown): v is Record<string, string> {
  return isObject(v) && Object.values(v).every((x) => typeof x === "string");
}

/** Whether `v` reads as a signed root, a root `notAfter` that is not an integer in [0, 2^53 − 1] included. */
function isSignedRoot(v: unknown): boolean {
  try {
    parseSignedRoot(v, "serverRoot");
    return true;
  } catch {
    return false;
  }
}

/**
 * The reply's shape; `serverKeyringSig`, `serverKeyringNotAfter` and `serverReplyCert` are optional, but each, when
 * present (even as null), must be well formed: a window, the keyring's or the root's, that is not an integer in
 * [0, 2^53 − 1] makes the reply malformed rather than old form.
 */
function isSessionReply(v: unknown): v is SessionReply {
  return (
    isObject(v) &&
    (v.serverRoot === null || isSignedRoot(v.serverRoot)) &&
    typeof v.serverPolicyKey === "string" &&
    isStringMap(v.serverKeyring) &&
    (!Object.hasOwn(v, "serverKeyringSig") || typeof v.serverKeyringSig === "string") &&
    (!Object.hasOwn(v, "serverKeyringNotAfter") || isNotAfter(v.serverKeyringNotAfter)) &&
    (!Object.hasOwn(v, "serverReplyCert") || isReplyCert(v.serverReplyCert)) &&
    typeof v.nonce === "string" &&
    typeof v.sess === "string" &&
    (v.status === "attested" || v.status === "unsafe") &&
    Array.isArray(v.disabled) &&
    v.disabled.every((d) => typeof d === "string") &&
    typeof v.sig === "string"
  );
}

/**
 * Checks a session handshake reply against the request it answers, the pinned server policy key, the server's
 * entry service from the client's own configuration, and the time `now` (ms): a reply that is not well formed, one
 * from another key than the pin, one that does not verify (live, see verifySessionReply), then its own status.
 * Never throws.
 */
export function checkSessionReply(raw: unknown, req: SessionRequest, pin: string, serverEntry: string, now: number): ReplyCheck {
  if (!isSessionReply(raw)) {
    return "MALFORMED_REPLY";
  }
  if (raw.serverPolicyKey !== pin) {
    return "PIN_MISMATCH";
  }
  if (!verifySessionReply(raw, req, pin, serverEntry, now)) {
    return "BAD_SIGNATURE";
  }
  return raw.status === "attested" ? "ATTESTED" : "UNSAFE";
}

/** A response check's policyNotAfter: the server root's window, and the keyring's too in the entry-key form, the only one where the keyring has its own policy-key signature; undefined (fails closed) when either is old form. */
export function serverPolicyNotAfter(reply: SessionReply): number | undefined {
  const root = reply.serverRoot?.notAfter;
  return Object.hasOwn(reply, "serverKeyringSig") ? earliestNotAfter(root, reply.serverKeyringNotAfter) : earliestNotAfter(root);
}
