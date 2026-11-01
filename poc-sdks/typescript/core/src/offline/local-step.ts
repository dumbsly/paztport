// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { canonicalize } from "../encoding/jcs.ts";
import { influenceClasses, readInfluence } from "../influence/influence.ts";
import { decideLocalCall, type LocalVerdict } from "../influence/local-decision.ts";
import { localReceiver, localStepBind, readLocalDecision, type LocalDecision } from "../influence/local-step.ts";
import { isNotAfter } from "../policy/validity.ts";
import { rulesHash, type LocalRules } from "../policy/local-rules.ts";
import type { ReasonCode } from "../verify/reason.ts";
import { verifyChainOffline, type Signers } from "./verify-offline.ts";

/** A local step as recorded: the call, the gate's decision on it, and its chain, the run's origin then the client hop. */
export type RecordedLocalStep = {
  tool: string;
  callId: string;
  rid: string;
  /** The time recorded with the step: its last stamp's `ts` must be this. */
  now: number;
  input: unknown;
  /** The decision's token: the call id, what was resolved, the verdict, whether the route is listed, the rules. */
  decision: string;
  /** The chain's token. */
  chain: string;
  /** The route's proof's token, null when the route is not listed. */
  proof: string | null;
  /** The influence list's token. */
  influence: string;
};

/** The client's material a step is checked against, which the caller has already checked under the client policy key. */
export type LocalStepClient = {
  keyring: Record<string, string>;
  root: Uint8Array;
  rootId: string;
  /** The root's `notAfter`. */
  rootNotAfter: number;
  /** The keyring's `notAfter`. */
  keyringNotAfter: number;
  rules: LocalRules | null;
};

/** The step's run in the record set: its recorded prompt and start times. */
export type RecordedRun = { prompt: string; ts: ReadonlySet<number> };

/**
 * A recorded local step's result. OK means the record verified, whatever the gate decided: `verdict`, set only then,
 * is the decision it signed, OK when the call was allowed and the refusal's code when it was not.
 */
export type LocalStepResult = { reason: ReasonCode; verdict?: LocalVerdict };

/** True when `window`, a `notAfter`, still holds at `at`; a malformed one never does. */
function within(window: number, at: number): boolean {
  return isNotAfter(window) && at <= window;
}

/**
 * Checks a recorded local step (verification.md §Offline verification, MCP profile), the first failure being its
 * result:
 * 1. the step binds its call and decision (BINDING_MISMATCH when the decision does not read, is for another call, or
 *    they can't be bound);
 * 2. its chain, by the offline chain verifier with `signers` (the origin service then the client hop, both on the
 *    client's one instance), `sess = ""`, the client's root and keyring, the receiver `local:<tool>` in the route and
 *    the nonce key `<rid>|<callId>|local`, spent in `seen`; an unproven route is how the gate's refusal of an unlisted
 *    tool verifies, so PATH_NOT_ALLOWED goes on;
 * 3. at the step's `ts`, the client's root and keyring are no later than their `notAfter` (POLICY_EXPIRED);
 * 4. the route verdict and proof it recorded are what its chain proves (PROOF_MISMATCH);
 * 5. the rules hash it signed is the client's (RULES_MISMATCH);
 * 6. the decision it signed, what was resolved and the verdict, is the one the signed rules give for what it recorded
 *    (VERDICT_MISMATCH).
 * The step's fields are read as typed: the caller reads them from its own record format first.
 */
export function verifyRecordedLocalStep(
  step: RecordedLocalStep,
  cfg: { client: LocalStepClient; signers: Signers; run?: RecordedRun; seen: Set<string> },
): LocalStepResult {
  const { client, signers, run } = cfg;
  const fail = (reason: ReasonCode): LocalStepResult => ({ reason });
  let decision: LocalDecision;
  let bind: string;
  try {
    decision = readLocalDecision(step.decision);
    if (decision.callId !== step.callId) {
      return fail("BINDING_MISMATCH");
    }
    bind = localStepBind({
      toolName: step.tool, toolCallId: step.callId, input: step.input, resolved: decision.resolved,
      verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash,
    });
  } catch {
    return fail("BINDING_MISMATCH");
  }
  const chain = verifyChainOffline(
    {
      chain: step.chain,
      expectedBind: bind,
      influence: step.influence,
      proof: step.proof,
      receiver: localReceiver(step.tool),
      receiverInRoute: true,
      rid: step.rid,
      recordedTs: { last: step.now, ...(run !== undefined ? { run: run.ts } : {}) },
      ...(run !== undefined ? { prompt: run.prompt } : {}),
    },
    {
      keyring: client.keyring,
      root: client.root,
      rootId: client.rootId,
      allowedOrigins: signers.svcs.slice(0, 1),
      sess: "",
      seen: cfg.seen,
      nonceKey: `${step.rid}|${step.callId}|local`,
      signers,
    },
  );
  if (chain.reason !== "OK" && chain.reason !== "PATH_NOT_ALLOWED") {
    return fail(chain.reason);
  }
  // judged at the step's own signed time, now that the chain check has tied `now` to its last stamp's ts
  if (!within(client.rootNotAfter, step.now) || !within(client.keyringNotAfter, step.now)) {
    return fail("POLICY_EXPIRED");
  }
  const proven = chain.reason === "OK";
  if (proven !== decision.routeAllowed || (!proven && step.proof !== null)) {
    return fail("PROOF_MISMATCH");
  }
  if (decision.rulesHash !== (client.rules === null ? null : rulesHash(client.rules))) {
    return fail("RULES_MISMATCH");
  }
  // the gate's own rule, applied to what it recorded: with the route not listed or no rules it resolves nothing
  const resolved = decision.resolved;
  // the chain committed to the influence, so its token reads
  const classes = influenceClasses(readInfluence(step.influence));
  const expected = decideLocalCall({
    routeAllowed: decision.routeAllowed, rules: client.rules, classes, resolve: () => resolved,
  });
  if (canonicalize(expected.resolved) !== canonicalize(resolved) || expected.verdict !== decision.verdict) {
    return fail("VERDICT_MISMATCH");
  }
  return { reason: "OK", verdict: decision.verdict };
}
