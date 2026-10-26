// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "./influence.ts";

/** What the rule sees of one piece of context: its class, and whose it is when it is private. */
export type InfluenceFact = { cls: InfluenceClass; owner?: string };

/**
 * The one standing influence rule, for every public destination: a write is refused when the context holds
 * untrusted content (third-party, or local-untrusted, which counts as such) and private content that is not
 * the destination owner's. An absent or empty owner, on a private fact or on the destination, is unknown and
 * fails closed. The caller takes `destinationOwner` from trusted records, never from content.
 */
export function publicWriteRefused(influence: readonly InfluenceFact[], destinationOwner?: string): boolean {
  if (!influence.some((f) => f.cls === "third-party" || f.cls === "local-untrusted")) {
    return false;
  }
  return influence.some(
    (f) => f.cls === "private" && (f.owner === undefined || f.owner === "" || destinationOwner === undefined || destinationOwner === "" || f.owner !== destinationOwner),
  );
}
