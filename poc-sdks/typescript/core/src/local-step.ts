// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindLocalTool } from "./binding.ts";
import { commitInfluence, type InfluenceEntry } from "./influence.ts";
import type { LocalVerdict, Resolved } from "./local-decision.ts";
import { signStampV2, type StampV2 } from "./stamp.ts";

/** What a local step signs: the call, the gate's decision on it, and the step's place in the run's chain. */
export type LocalStepFields = {
  svc: string;
  inst: string;
  rid: string;
  ts: number;
  /** The signature of the run's origin stamp. */
  prev: string;
  toolName: string;
  toolCallId: string;
  /** The input as recorded in the evidence. */
  input: unknown;
  resolved: Resolved;
  verdict: LocalVerdict;
  /** Whether the session's route list has the tool. */
  listed: boolean;
  /** rulesHash of the rules that decided, null with none. */
  rulesHash: string | null;
  /** The influence the call was decided under. */
  influence: InfluenceEntry[];
};

/**
 * A local tool call as a signed client-mesh step: a v2 stamp with an empty `sess`, bound to the input and the
 * decision (the call id, what was resolved, the verdict, whether the route is listed and which rules decided),
 * so none of them can be changed in the evidence after signing.
 */
export function stampLocalStep(f: LocalStepFields, privateKey: string): StampV2 {
  const bind = bindLocalTool(f.toolName, f.input, {
    callId: f.toolCallId,
    resolved: f.resolved,
    verdict: f.verdict,
    routeAllowed: f.listed,
    rulesHash: f.rulesHash,
  });
  return signStampV2({ svc: f.svc, inst: f.inst, rid: f.rid, ts: f.ts, sess: "", bind, infl: commitInfluence(f.influence), prev: f.prev }, privateKey);
}
