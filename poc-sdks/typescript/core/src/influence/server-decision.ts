// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "./influence.ts";
import { guardedWriteRefused, type InfluenceFact } from "./influence-rule.ts";

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
 * The server's decision on a tools/call, once any chain it carries has verified and its items have read (spec
 * sessions.md, The server decision). In an attested session a server that acts on influence decides a write to a
 * public destination by the every-stamp rule, then the owner-aware rule over the request's entries and the classes
 * `served` in the session (spec influence.md, Over MCP); one that does not act on it allows the call. Otherwise (an
 * unsafe session, or no handshake yet) the tools in `disabledWhenUnsafe` are refused and every other tool runs
 * ungated.
 */
export function decideServerCall(opts: {
  tool: string;
  isWrite: boolean;
  publicDestination: boolean;
  /** True only for a session opened as attested. */
  attested: boolean;
  /** Whether the server acts on influence; without it an attested call is allowed. */
  actsOnInfluence: boolean;
  /** Every class this server has attested in a response in the session. */
  served: Iterable<InfluenceClass>;
  /** What the call's blocks hold: their entries, and whether every stamp names `influence`. */
  request: { entries: readonly InfluenceFact[]; everyStampNames: boolean };
  disabledWhenUnsafe: readonly string[];
  destinationOwner?: string;
}): "OK" | "UNSAFE_SESSION" | "INFLUENCE_DENIED" {
  if (!opts.attested) {
    return opts.disabledWhenUnsafe.includes(opts.tool) ? "UNSAFE_SESSION" : "OK";
  }
  if (!opts.actsOnInfluence || !opts.isWrite || !opts.publicDestination) {
    return "OK";
  }
  const facts = contextInfluence(opts.request.entries, opts.served);
  return guardedWriteRefused(opts.request.everyStampNames, facts, opts.destinationOwner) ? "INFLUENCE_DENIED" : "OK";
}
