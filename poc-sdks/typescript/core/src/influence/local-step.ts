// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindLocalTool } from "../stamp/binding.ts";
import { commitInfluence, type InfluenceEntry } from "./influence.ts";
import type { LocalVerdict, Resolved } from "./local-decision.ts";
import { signStampV3, type StampV3 } from "../stamp/stamp.ts";

/** What a local tool's receiver starts with: its route names `local:<tool>` after the client chain. */
export const LOCAL_RECEIVER_PREFIX = "local:";

/** The receiver a local tool call names, `local:<tool>`. */
export function localReceiver(tool: string): string {
  return LOCAL_RECEIVER_PREFIX + tool;
}

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
 * A local tool call as a signed client-mesh step: a v3 stamp with an empty `sess`, naming `local:<tool>` as its
 * receiver, bound to the input and the decision (the call id, what was resolved, the verdict, whether the route
 * is listed and which rules decided), so none of them can be changed in the evidence after signing.
 */
export function stampLocalStep(f: LocalStepFields, privateKey: string): StampV3 {
  const bind = localStepBind(f);
  return signStampV3(
    { svc: f.svc, inst: f.inst, rid: f.rid, ts: f.ts, sess: "", rcv: localReceiver(f.toolName), bind, infl: commitInfluence(f.influence), prev: f.prev },
    privateKey,
  );
}

/** The binding a local step's stamp carries: the call and the decision on it. Throws if the input can't be bound. */
export function localStepBind(f: Pick<LocalStepFields, "toolName" | "toolCallId" | "input" | "resolved" | "verdict" | "listed" | "rulesHash">): string {
  return bindLocalTool(f.toolName, f.input, {
    callId: f.toolCallId,
    resolved: f.resolved,
    verdict: f.verdict,
    routeAllowed: f.listed,
    rulesHash: f.rulesHash,
  });
}
