// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { callInSession, type RecordedSession } from "../offline/records.ts";
import type { StampItems } from "../verify/extensions.ts";
import type { ReasonCode } from "../verify/reason.ts";
import type { ChainVerification } from "../verify/verify-chain.ts";
import { entryOf, INFLUENCE, type InfluenceEntry } from "./influence.ts";

/**
 * What a request's received blocks hold for influence: the entries, and whether every stamp names `influence`, when
 * every item reads as an entry; otherwise the signer of the first block holding an item that does not, for the
 * operator's log, since the code names no one.
 */
export type RequestInfluence =
  | { reads: true; entries: InfluenceEntry[]; everyStampNames: boolean }
  | { reads: false; signer: string };

/**
 * Reads the items handed on under `influence`, one entry of `stamps` per stamp in chain order (spec influence.md, The
 * every-stamp rule and Entries): every item of every block, in order, each read as an entry. `everyStampNames` is
 * false when a block does not name `influence`, and true when there is no stamp to read, since the rule cannot refuse
 * for what it is not shown (What the rules read). What the service adds itself is the caller's to add.
 */
export function readRequestInfluence(stamps: readonly StampItems[]): RequestInfluence {
  const entries: InfluenceEntry[] = [];
  let everyStampNames = true;
  for (const { svc, items } of stamps) {
    if (items === null) {
      everyStampNames = false;
      continue;
    }
    try {
      entries.push(...items.map(entryOf));
    } catch {
      return { reads: false, signer: svc };
    }
  }
  return { reads: true, entries, everyStampNames };
}

/**
 * The result a service that acts on `influence` gives a request it verified: INFLUENCE_MISMATCH when the verifier
 * gave OK and an item handed on under `influence` does not read as an entry, else the verifier's reason. A
 * verification whose hand-over holds no `influence` is that of a service that does not act on it, and stands.
 */
export function influenceReason(v: ChainVerification): ReasonCode {
  const stamps = v.ok ? v.handOver?.get(INFLUENCE) : undefined;
  if (stamps === undefined) return v.reason;
  return readRequestInfluence(stamps).reads ? v.reason : "INFLUENCE_MISMATCH";
}

/**
 * A recorded call's result at an offline verifier that acts on `influence` (spec verification.md, Offline
 * verification, row 9): the extension's reading of the items once the offline order gives OK (`influenceReason`), and
 * only then the session's limits at `at`, the call's last stamp's `ts` (`callInSession`). So a call past its session's
 * limits that holds an item that does not read is INFLUENCE_MISMATCH, not OUTSIDE_SESSION. Undefined, as
 * `callInSession` gives it, for a session that is not attested at all.
 */
export function recordedCallReason(v: ChainVerification, session: RecordedSession, at: number): ReasonCode | undefined {
  return callInSession(session, influenceReason(v), at);
}
