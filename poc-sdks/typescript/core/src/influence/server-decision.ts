// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "./influence.ts";
import { publicWriteRefused, type InfluenceFact } from "./influence-rule.ts";

/** The influence rule applied to a tool call: only a write to a public destination is decided by it. */
export function publicWriteDecision(
  isWrite: boolean,
  publicDestination: boolean,
  influence: readonly InfluenceFact[],
  destinationOwner?: string,
): "OK" | "INFLUENCE_DENIED" {
  if (!isWrite || !publicDestination) return "OK";
  return publicWriteRefused(influence, destinationOwner) ? "INFLUENCE_DENIED" : "OK";
}

/**
 * What the influence rule sees in an attested session: the client's verified influence plus every
 * class this server served in the session. A served class carries no owner. The union only adds
 * facts, so the server is stricter, never looser, than the harness: a client that fails to record a
 * private (or third-party) label cannot launder it past the rule.
 */
function contextInfluence(clientInfluence: readonly InfluenceFact[], served: Iterable<InfluenceClass>): InfluenceFact[] {
  return [...clientInfluence, ...[...served].map((cls) => ({ cls }))];
}

/**
 * The server's decision on a tools/call, once any chain it carries has verified (`clientInfluence` is
 * then the verified call's influence). In an attested session the influence rule decides, over the union of
 * the client's influence and the classes `served` in the session. Otherwise (an unsafe session, or no
 * handshake yet) the tools in `disabledWhenUnsafe` are refused and every other tool runs ungated.
 */
export function decideServerCall(opts: {
  tool: string;
  isWrite: boolean;
  publicDestination: boolean;
  /** True only for a session opened as attested. */
  attested: boolean;
  /** Every class this server has attested in a response in the session. */
  served: Iterable<InfluenceClass>;
  clientInfluence: readonly InfluenceFact[];
  disabledWhenUnsafe: readonly string[];
  destinationOwner?: string;
}): "OK" | "UNSAFE_SESSION" | "INFLUENCE_DENIED" {
  if (opts.attested) {
    return publicWriteDecision(opts.isWrite, opts.publicDestination, contextInfluence(opts.clientInfluence, opts.served), opts.destinationOwner);
  }
  return opts.disabledWhenUnsafe.includes(opts.tool) ? "UNSAFE_SESSION" : "OK";
}
