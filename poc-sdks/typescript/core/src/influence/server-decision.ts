// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { StampItems } from "../verify/extensions.ts";
import type { InfluenceClass } from "./influence.ts";
import { guardedWriteRefused, type InfluenceFact } from "./influence-rule.ts";
import { readRequestInfluence } from "./request.ts";

/**
 * What the influence rule sees in an attested session: the request's influence plus every class this server served
 * in the session. A served class carries no owner. The union only adds facts, so the server is stricter, never
 * looser, than the harness: a client that fails to record a private (or third-party) label cannot launder it past
 * the rule.
 */
function contextInfluence(request: readonly InfluenceFact[], served: Iterable<InfluenceClass>): InfluenceFact[] {
  return [...request, ...[...served].map((cls) => ({ cls }))];
}

/**
 * The decision of a server that acts on influence on a call that verified in an attested session (spec sessions.md,
 * The server decision, steps 2 and 3), given `stamps`, the items the verifier handed on under `influence`, one entry
 * per stamp in chain order. First every item must read as an entry: one that does not gives readRequestInfluence's
 * code, with the signer of the first block holding one, for the operator's log, since the code names no one. Only
 * then is a write to a public destination decided, by the every-stamp rule and then the owner-aware rule over the
 * entries and the classes `served` in the session (spec influence.md, Over MCP); anything else is allowed.
 */
export function decideVerifiedCall(
  stamps: readonly StampItems[],
  opts: {
    isWrite: boolean;
    publicDestination: boolean;
    /** Every class this server has attested in a response in the session. */
    served: Iterable<InfluenceClass>;
    destinationOwner?: string;
  },
): { verdict: "OK" | "INFLUENCE_DENIED" } | { verdict: "INFLUENCE_MISMATCH"; signer: string } {
  const read = readRequestInfluence(stamps);
  if (!read.reads) {
    return { verdict: read.reason, signer: read.signer };
  }
  if (!opts.isWrite || !opts.publicDestination) {
    return { verdict: "OK" };
  }
  const facts = contextInfluence(read.entries, opts.served);
  const refused = guardedWriteRefused(read.everyStampNames, facts, opts.destinationOwner);
  return { verdict: refused ? "INFLUENCE_DENIED" : "OK" };
}
