// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  canonicalize,
  decode,
  provesPath,
  readKeyring,
  readLocalRules,
  readProof,
  readRoot,
  rulesHash,
  rulesRoute,
  verifyKeyring,
  verifyRecordedLocalStep,
  verifyRoot,
  type LocalRules,
  type LocalStepClient,
  type ReasonCode,
  type SignedRoot,
} from "@paztport/core";

/**
 * Offline checks of the pi extension's local steps, used by verify.ts. The extension writes a
 * `client` record (the client mesh: the signed keyring and root, the local rules and their proof, each as its token)
 * at session start, and then one `local` record per gated built-in tool call.
 *
 * The client record verifies when its keyring reads (its names are route nodes) and is signed by its own policy key,
 * its root reads and verifies against that key, every session record in the file that names a client root names this
 * root with the same policy key, keyring and keyring window, and, when it has rules, the rules read and `rulesProof`
 * proves `session/pi/rules:<rulesHash(rules)>` against the root. With no rules, `rulesProof` must be null. A token
 * that is not a string or does not read fails the record, as a root or keyring without its window does. The client
 * policy key is trusted on first use from the file, as it is in session records (where the server's signed reply
 * binds it); verify pins no client key of its own.
 *
 * A local record is checked against the latest client record before it, the first failure being its result: its call
 * fields (`tool`, `callId`, `rid`, `now`, `input`) are well formed (UNREADABLE); there is a verified client record
 * (NO_CLIENT); then the library's recorded local step check, verifyRecordedLocalStep (verification.md §Offline
 * verification, MCP profile), with this demo's signers: the origin is svc "session" and the step svc "pi", both on
 * inst "pi-1". It reads the record's `decision`, `chain`, `proof` and `influence` tokens, each refused as its reader
 * refuses it, and its order is in its own comment: the binding of the call and the decision (BINDING_MISMATCH, also
 * for a decision that does not read), the chain with every offline check (the run's recorded prompt and start times,
 * and the file's spent keys), POLICY_EXPIRED against the client record's root and keyring at the step's time,
 * PROOF_MISMATCH, RULES_MISMATCH and VERDICT_MISMATCH. The client signs the step's time itself: verify relies on it,
 * as on every recorded time, but no edit moves a window. A verified step is OK when it was allowed and REFUSED when it
 * was refused: local refusals are signed and checked, unlike the server's. A chain is v3, its stamps naming pi and
 * then `local:<tool>` as their receivers (BINDING_MISMATCH).
 *
 * Verify does not look at the disk: it checks that the rules were applied correctly to what the gate saw, not
 * that the gate saw the disk correctly. Freshness windows do not apply offline: a local step is checked against
 * the times recorded with it.
 */
export type LocalResult = "OK" | "REFUSED" | "UNREADABLE" | ReasonCode | "BAD_CLIENT" | "NO_CLIENT";

/** What a verified client record gives the local records that follow it: the client material the library checks a step against. */
export type Client = LocalStepClient;

/** A client root, policy key, keyring and keyring window that a session record in the file names. */
export type NamedClient = { root: SignedRoot; policyKey: string; keyring: Readonly<Record<string, string>>; keyringNotAfter: number };

/** A rid's run: its undisputed prompt and the times its run records give. */
export type RunInfo = { prompt: string; ts: ReadonlySet<number> };

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";
/** A record's token as the library reads it: one that is not a string is "", a token that does not read. */
const token = (v: unknown): string => (isString(v) ? v : "");

/** The service the agents demo's run origin signs as; its client policy and servers name it too. */
export const ORIGIN_SVC = "session";

const INST = "pi-1";
/** A local step's chain: the run's origin, then the pi stamp, both from the one pi instance. */
const SIGNERS = { svcs: [ORIGIN_SVC, "pi"], inst: INST };

/** The verified client record, or undefined when it does not verify (see the module comment). */
export function verifyClient(r: Rec, named: NamedClient[]): Client | undefined {
  try {
    if (!isString(r.keyring) || !isString(r.root)) {
      return undefined;
    }
    // each throws on a token that does not read; a keyring name that is not a route node does not read
    const ring = readKeyring(r.keyring);
    const signedRoot = readRoot(r.root);
    if (!verifyKeyring(ring, ring.policy) || !verifyRoot(signedRoot, ring.policy)) {
      return undefined;
    }
    // the session's request is bound by the server's signed reply: a client record must agree with it
    for (const n of named) {
      if (
        canonicalize(n.root) !== canonicalize(signedRoot) ||
        n.policyKey !== ring.policy ||
        canonicalize(n.keyring) !== canonicalize(ring.services) ||
        n.keyringNotAfter !== ring.notAfter
      ) {
        return undefined;
      }
    }
    const root = decode(signedRoot.root);
    let rules: LocalRules | null = null;
    if (r.rules !== null) {
      if (!isString(r.rules) || !isString(r.rulesProof)) {
        return undefined;
      }
      rules = readLocalRules(r.rules);
      const rulesProof = readProof(r.rulesProof);
      if (!provesPath(rulesProof, rulesRoute(SIGNERS.svcs, rulesHash(rules)), root, signedRoot.rootId)) {
        return undefined;
      }
    } else if (r.rulesProof !== null) {
      return undefined;
    }
    return {
      keyring: ring.services as Record<string, string>,
      root,
      rootId: signedRoot.rootId,
      rootNotAfter: signedRoot.notAfter,
      keyringNotAfter: ring.notAfter,
      rules,
    };
  } catch {
    return undefined;
  }
}

/**
 * Checks one local record (see the module comment). `seen` is the file's set of spent nonce keys, shared with
 * its calls and updated here; `runOf` gives a rid's run, or undefined when it has none or its prompt is in dispute.
 */
export function verifyLocal(
  r: Rec,
  client: Client | undefined,
  runOf: (rid: string) => RunInfo | undefined,
  seen: Set<string>,
): LocalResult {
  if (!isString(r.tool) || !isString(r.callId) || !isString(r.rid) || typeof r.now !== "number" || !isObject(r.input)) {
    return "UNREADABLE";
  }
  if (client === undefined) {
    return "NO_CLIENT";
  }
  const step = {
    tool: r.tool, callId: r.callId, rid: r.rid, now: r.now, input: r.input, decision: token(r.decision), chain: token(r.chain),
    proof: r.proof === null ? null : token(r.proof), influence: token(r.influence),
  };
  const run = runOf(r.rid);
  const v = verifyRecordedLocalStep(step, { client, signers: SIGNERS, ...(run !== undefined ? { run } : {}), seen });
  if (v.reason !== "OK") {
    return v.reason;
  }
  return v.verdict === "OK" ? "OK" : "REFUSED";
}
