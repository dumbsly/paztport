// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readToken, type JsonValue } from "../encoding/json.ts";
import { readSessionRequest } from "../session/request.ts";
import { isAttestedSession, type SessionRequest } from "../session/session.ts";
import { NonceCache } from "../verify/nonce.ts";
import type { ReasonCode } from "../verify/reason.ts";

/**
 * A handshake read back from a record set: the request and reply as recorded, as their tokens, the server policy key
 * the client pinned, and the server's entry service from the verifier's own configuration, never the record's.
 */
export type RecordedHandshake = {
  request: string;
  reply: string;
  pin: string;
  serverEntry: string;
};

/** What a recorded handshake gives the records that rely on it (sessions-and-influence.md §Recorded handshakes). */
export type RecordedSession = {
  /** Whether it opened an attested session, judged at `at`: a time the client signed, a call's last stamp `ts`, never one read from the handshake record. */
  attestedAt: (at: number) => boolean;
  /** Attested at all: judged at the earliest of its limits, since each is an upper bound. */
  attested: boolean;
  /** The `policyNotAfter` a recorded response in the session is checked with: the server root's window and, in the entry-key form, the server keyring's; 2^53 − 1 when the reply holds neither (it then opens no attested session). */
  responseNotAfter: number;
};

/** `o`'s own `field` when `o` is an object and that is an integer, else undefined: a limit the record lacks. */
function ownWindow(o: JsonValue | undefined, field: string): number | undefined {
  if (typeof o !== "object" || o === null || Array.isArray(o) || !Object.hasOwn(o, field)) return undefined;
  const n = o[field];
  return typeof n === "number" ? n : undefined;
}

/** What `read` reads, or undefined when the record does not read. */
function readOr<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/** The earliest of `windows`, or `none` when no item has one. */
function earliest(windows: (number | undefined)[], none: number): number {
  const set = windows.filter((w): w is number => w !== undefined);
  return set.length === 0 ? none : Math.min(...set);
}

/**
 * Reads a recorded handshake; a request or reply that does not read is a handshake that opened no attested session.
 * Its limits are the certificate's `notAfter` (entry-key form) and the `notAfter` of each
 * root and keyring, both sides; it is attested at all when attested at the earliest of them. The windows are read
 * before the signatures over them are checked, but none counts unless the session is attested at it, which checks each signature. A
 * response is limited only by the server's root and, in the entry-key form, its keyring: the client's windows and the
 * certificate do not limit it. Never throws.
 */
export function recordedSession(h: RecordedHandshake): RecordedSession {
  const { pin, serverEntry } = h;
  const request: SessionRequest | undefined = readOr(() => readSessionRequest(h.request));
  // The reply's windows are read from its value whether or not it is a well-formed reply.
  const value = readOr(() => readToken(h.reply));
  const reply = typeof value === "object" && value !== null && !Array.isArray(value) ? value : undefined;
  const attestedAt = (at: number) => request !== undefined && isAttestedSession(request, h.reply, pin, serverEntry, at);
  const limit = earliest(
    [
      ownWindow(reply?.serverReplyCert, "notAfter"),
      request?.clientRoot?.notAfter,
      request?.clientKeyringNotAfter,
      ownWindow(reply?.serverRoot, "notAfter"),
      ownWindow(reply, "serverKeyringNotAfter"),
    ],
    0,
  );
  const entryKeyForm = reply !== undefined && Object.hasOwn(reply, "serverKeyringSig");
  const ring = entryKeyForm ? ownWindow(reply, "serverKeyringNotAfter") : undefined;
  return {
    attestedAt,
    attested: attestedAt(limit),
    responseNotAfter: earliest([ownWindow(reply?.serverRoot, "notAfter"), ring], Number.MAX_SAFE_INTEGER),
  };
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
