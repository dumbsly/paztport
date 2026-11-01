// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isNotAfter } from "../policy/validity.ts";
import { readSessionReply, verifySessionReply, type SessionReply, type SessionRequest } from "./session.ts";

/** What a client concludes from a handshake reply: the vocabulary of the spec's session-reply vectors. */
export type ReplyCheck = "ATTESTED" | "UNSAFE" | "MALFORMED_REPLY" | "PIN_MISMATCH" | "BAD_SIGNATURE";

/**
 * Checks a session handshake reply, given as its token, against the request it answers, the pinned server policy
 * key, the server's entry service from the client's own configuration, and the time `now` (ms): a reply that does
 * not read (readSessionReply), one from another key than the pin, one that does not verify (live, see
 * verifySessionReply), then its own status. Never throws.
 */
export function checkSessionReply(
  reply: string,
  req: SessionRequest,
  pin: string,
  serverEntry: string,
  now: number,
): ReplyCheck {
  let read: SessionReply;
  try {
    read = readSessionReply(reply);
  } catch {
    return "MALFORMED_REPLY";
  }
  if (read.serverPolicyKey !== pin) {
    return "PIN_MISMATCH";
  }
  if (!verifySessionReply(read, req, pin, serverEntry, now)) {
    return "BAD_SIGNATURE";
  }
  return read.status === "attested" ? "ATTESTED" : "UNSAFE";
}

/**
 * A response check's policyNotAfter: the server root's window, and the keyring's too in the entry-key form, the only
 * one where the keyring has its own policy-key signature. A reply the client's check accepted with a root holds each;
 * for one that lacks either it is NaN, which every response check refuses as POLICY_EXPIRED.
 */
export function serverPolicyNotAfter(reply: SessionReply): number {
  const windows = [reply.serverRoot?.notAfter, ...(Object.hasOwn(reply, "serverKeyringSig") ? [reply.serverKeyringNotAfter] : [])];
  return windows.every(isNotAfter) ? Math.min(...windows) : Number.NaN;
}
