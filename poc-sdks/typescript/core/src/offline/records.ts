// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isNotAfter } from "../policy/validity.ts";
import { isReplyCert } from "../session/reply-cert.ts";
import { isAttestedSession, isLegacySessionRequest, type LegacySessionRequest, type SessionReply, type SessionRequest } from "../session/session.ts";
import { NonceCache } from "../verify/nonce.ts";
import type { ReasonCode } from "../verify/reason.ts";

/**
 * A handshake read back from a record set: the request and reply as recorded, the server policy key the client
 * pinned, and the server's entry service from the verifier's own configuration, never the record's.
 */
export type RecordedHandshake = {
  request: SessionRequest | LegacySessionRequest;
  reply: SessionReply;
  pin: string;
  serverEntry: string;
};

/** What a recorded handshake gives the records that rely on it (sessions-and-influence.md §Recorded handshakes). */
export type RecordedSession = {
  /** Whether it opened an attested session, judged at `at`: a time the client signed, a call's last stamp `ts`, never one read from the handshake record. */
  attestedAt: (at: number) => boolean;
  /** Attested at all: judged at the earliest of its limits, since each is an upper bound. */
  attested: boolean;
  /** The `policyNotAfter` a recorded response in the session is checked with: the server root's window and, in the entry-key form, the server keyring's; 2^53 − 1 when neither has one. */
  responseNotAfter: number;
  /** Attested from a request with no `clientKeyringSig`; never set on one that is not attested, since a failure is never marked. */
  legacy: boolean;
};

/** `o`'s own `field` when it is a valid notAfter, else undefined: offline an old-form root or keyring sets no limit. */
function ownWindow(o: unknown, field: string): number | undefined {
  if (typeof o !== "object" || o === null || !Object.hasOwn(o, field)) return undefined;
  const n = (o as Record<string, unknown>)[field];
  return isNotAfter(n) ? n : undefined;
}

/** The earliest of `windows`, or `none` when no item has one. */
function earliest(windows: (number | undefined)[], none: number): number {
  const set = windows.filter((w): w is number => w !== undefined);
  return set.length === 0 ? none : Math.min(...set);
}

/**
 * Reads a recorded handshake. Its limits are the certificate's `notAfter` (entry-key form) and the `notAfter` of each
 * root and keyring in the new form, both sides; it is attested at all when attested at the earliest of them, or at
 * any time when it has none (a policy-key reply over old-form material). The windows are read before the signatures
 * over them are checked, but none counts unless the session is attested at it, which checks each signature. A
 * response is limited only by the server's root and, in the entry-key form, its keyring: the client's windows and the
 * certificate do not limit it. Never throws.
 */
export function recordedSession(h: RecordedHandshake): RecordedSession {
  const { request, reply, pin, serverEntry } = h;
  const attestedAt = (at: number) => isAttestedSession(request, reply, pin, serverEntry, at);
  try {
    const limit = earliest(
      [
        isReplyCert(reply.serverReplyCert) ? reply.serverReplyCert.notAfter : undefined,
        ownWindow(request.clientRoot, "notAfter"),
        ownWindow(request, "clientKeyringNotAfter"),
        ownWindow(reply.serverRoot, "notAfter"),
        ownWindow(reply, "serverKeyringNotAfter"),
      ],
      0,
    );
    const ring = Object.hasOwn(reply, "serverKeyringSig") ? ownWindow(reply, "serverKeyringNotAfter") : undefined;
    const attested = attestedAt(limit);
    return {
      attestedAt,
      attested,
      responseNotAfter: earliest([ownWindow(reply.serverRoot, "notAfter"), ring], Number.MAX_SAFE_INTEGER),
      legacy: attested && isLegacySessionRequest(request),
    };
  } catch {
    return { attestedAt: () => false, attested: false, responseNotAfter: Number.MAX_SAFE_INTEGER, legacy: false };
  }
}

/**
 * A recorded call's result in its session (verification.md §Offline verification): OUTSIDE_SESSION when the call
 * otherwise verifies (`reason` is OK) but its last stamp's `ts`, `at`, is past one of the session's limits; else
 * `reason`. Undefined for a session that is not attested at all: the spec gives a call relying on one no result,
 * so the record set's reader reports it.
 */
export function callInSession(session: RecordedSession, reason: ReasonCode, at: number): ReasonCode | undefined {
  if (!session.attested) return undefined;
  return reason === "OK" && !session.attestedAt(at) ? "OUTSIDE_SESSION" : reason;
}

/**
 * One record set's replay state (verification.md §Offline verification, check 10): the nonce keys spent by its calls
 * and local steps, one set for the whole set, and one nonce cache for its responses that never forgets. A live cache
 * forgets keys after its window, which offline would let a copy pass once a later record is far enough on. Nothing
 * in a session record resets either: a repeated handshake leaves them as they are.
 */
export type RecordSet = { spent: Set<string>; responseNonces: NonceCache };

/** A record set's replay state, empty. */
export function newRecordSet(): RecordSet {
  return { spent: new Set<string>(), responseNonces: new NonceCache(Number.POSITIVE_INFINITY) };
}
