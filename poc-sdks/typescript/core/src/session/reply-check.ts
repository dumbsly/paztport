// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { earliestNotAfter } from "../policy/validity.ts";
import { isSessionReply, verifySessionReply, type SessionReply, type SessionRequest } from "./session.ts";

/** What a client concludes from a handshake reply: the vocabulary of the spec's session-reply vectors. */
export type ReplyCheck = "ATTESTED" | "UNSAFE" | "MALFORMED_REPLY" | "PIN_MISMATCH" | "BAD_SIGNATURE";

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
