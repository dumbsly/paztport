// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { ResponderEvent } from "./verifier.ts";

/** The codes that report what the sender did; any other reason (the verifier's own policy running out, a sound chain refused for what shaped it, offline-only and client-local codes, OK) names no one to act against. */
const ATTRIBUTABLE_REASONS: ReadonlySet<string> = new Set([
  "CHAIN_MISSING",
  "BAD_ORIGIN",
  "BAD_SIGNATURE",
  "BROKEN_LINK",
  "EXPIRED",
  "RID_MISMATCH",
  "BINDING_MISMATCH",
  "REPLAY",
  "PATH_NOT_ALLOWED",
  "SESSION_UNKNOWN",
  "CLIENT_PATH_NOT_ALLOWED",
  "INFLUENCE_MISMATCH",
  "PEER_MISMATCH",
]);

/** Whether a responder may act against the event's suspect: not an audit measurement, a named suspect, and a reason from the fail-closed allow-list. */
export function isAttributable(event: ResponderEvent): boolean {
  return !event.audit && event.suspectSvc !== "" && event.suspectInst !== "" && ATTRIBUTABLE_REASONS.has(event.reason);
}
