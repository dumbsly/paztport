// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  canonicalize,
  decode,
  parseLocalRules,
  parseProof,
  parseSignedRoot,
  provesPath,
  readNotAfter,
  rulesHash,
  rulesRoute,
  verifyKeyring,
  verifyRecordedLocalStep,
  verifyRoot,
  writeToken,
  type JsonValue,
  type LocalRules,
  type LocalStepClient,
  type LocalVerdict,
  type ReasonCode,
  type Resolved,
} from "@paztport/core";

/**
 * Offline checks of the pi extension's local steps, used by verify.ts. The extension writes a
 * `client` record (the client mesh: keyring, policy key, signed root, local rules and their proof) at session
 * start, and then one `local` record per gated built-in tool call.
 *
 * The client record verifies when its root verifies against its policy key, every session record in the file
 * that names a client root names this root with the same policy key and keyring, and, when it has rules, the
 * rules parse and `rulesProof` proves `session/pi/rules:<rulesHash(rules)>` against the root. With no rules,
 * `rulesProof` must be null. A `keyringSig` must be the policy key's signature over the keyring and
 * `keyringNotAfter`; a record without a `keyringSig`, or with an empty or non-string one, fails like any other
 * malformed client record. The root is checked whole; a window, the root's or the keyring's, that is missing or not
 * an integer in [0, 2^53 − 1] fails the record. Each session record must name the same root, policy key, keyring
 * and keyring window. The client policy key is trusted on first use from the file, as it is in session records
 * (where the server's signed reply binds it); verify pins no client key of its own.
 *
 * A local record is checked against the latest client record before it, the first failure being its result: its
 * fields are well formed, and its chain, proof and influence are values a token can carry (UNREADABLE); there is
 * a verified client record (NO_CLIENT); then the library's recorded local step check, verifyRecordedLocalStep
 * (verification.md §Offline verification, MCP profile), with this demo's signers: the origin is svc "session" and
 * the step svc "pi", both on inst "pi-1". That check's order is in its own comment: the binding of the call and
 * the decision (BINDING_MISMATCH), the chain with every offline check (the run's recorded prompt and start times,
 * and the file's spent keys), POLICY_EXPIRED against the client record's root and keyring at the step's time,
 * PROOF_MISMATCH, RULES_MISMATCH and VERDICT_MISMATCH. The client signs the step's time itself: verify relies on
 * it, as on every recorded time, but no edit moves a window. A verified step is OK when it was allowed and
 * REFUSED when it was refused: local refusals are signed and checked, unlike the server's. A chain is v3, its
 * stamps naming pi and then `local:<tool>` as their receivers (BINDING_MISMATCH).
 *
 * Verify does not look at the disk: it checks that the rules were applied correctly to what the gate saw, not
 * that the gate saw the disk correctly. Freshness windows do not apply offline: a local step is checked against
 * the times recorded with it.
 */
export type LocalResult = "OK" | "REFUSED" | "UNREADABLE" | ReasonCode | "BAD_CLIENT" | "NO_CLIENT";

/** What a verified client record gives the local records that follow it: the client material the library checks a step against. */
export type Client = LocalStepClient;

/** A client root, policy key, keyring and keyring window that a session record in the file names. */
export type NamedClient = { root: unknown; policyKey: unknown; keyring: unknown; keyringNotAfter: unknown };

/** A rid's run: its undisputed prompt and the times its run records give. */
export type RunInfo = { prompt: string; ts: ReadonlySet<number> };

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";

/** The service the agents demo's run origin signs as; its client policy and servers name it too. */
export const ORIGIN_SVC = "session";

const INST = "pi-1";
/** A local step's chain: the run's origin, then the pi stamp, both from the one pi instance. */
const SIGNERS = { svcs: [ORIGIN_SVC, "pi"], inst: INST };
const VERDICTS: readonly string[] = ["OK", "PATH_NOT_ALLOWED", "SCOPE_DENIED", "UNCHECKABLE", "INFLUENCE_DENIED"] satisfies LocalVerdict[];
const NEEDS: readonly string[] = ["read", "write", "exec"];
const VIAS: readonly string[] = ["list", "folder", "never", "missing", "uncheckable"];

/** The verified client record, or undefined when it does not verify (see the module comment). */
export function verifyClient(r: Rec, named: NamedClient[]): Client | undefined {
  try {
    const sr = r.signedRoot;
    const keyring = r.keyring;
    if (!isObject(keyring) || !Object.values(keyring).every(isString) || !isString(r.policyPublicKey)) {
      return undefined;
    }
    const signedRoot = parseSignedRoot(sr, "signedRoot"); // throws on a malformed root or window
    if (!verifyRoot(signedRoot, r.policyPublicKey)) {
      return undefined;
    }
    const services = keyring as Record<string, string>;
    const keyringNotAfter = readNotAfter(r, "keyringNotAfter"); // throws on a malformed window
    if (!isString(r.keyringSig) || r.keyringSig === "") {
      return undefined;
    }
    if (!verifyKeyring({ policy: r.policyPublicKey, services, sig: r.keyringSig, notAfter: keyringNotAfter }, r.policyPublicKey)) {
      return undefined;
    }
    // the session's request is bound by the server's signed reply: a client record must agree with it
    for (const n of named) {
      if (
        canonicalize(n.root) !== canonicalize(signedRoot) ||
        n.policyKey !== r.policyPublicKey ||
        canonicalize(n.keyring) !== canonicalize(keyring) ||
        n.keyringNotAfter !== keyringNotAfter
      ) {
        return undefined;
      }
    }
    const root = decode(signedRoot.root);
    let rules: LocalRules | null = null;
    let hash: string | null = null;
    if (r.rules !== null) {
      rules = parseLocalRules(r.rules); // throws on rules that don't parse
      hash = rulesHash(rules);
      if (!provesPath(parseProof(r.rulesProof), rulesRoute(SIGNERS.svcs, hash), root, signedRoot.rootId)) {
        return undefined;
      }
    } else if (r.rulesProof !== null) {
      return undefined;
    }
    return {
      keyring: keyring as Record<string, string>,
      root,
      rootId: signedRoot.rootId,
      rootNotAfter: signedRoot.notAfter,
      keyringNotAfter,
      rules,
    };
  } catch {
    return undefined;
  }
}

function isResolved(v: unknown): v is Resolved {
  return (
    isObject(v) &&
    (v.parse === "ok" || v.parse === "error") &&
    typeof v.readOnly === "boolean" &&
    Array.isArray(v.paths) &&
    v.paths.every((p) => isObject(p) && isString(p.at) && isString(p.need) && NEEDS.includes(p.need)) &&
    Array.isArray(v.programs) &&
    v.programs.every((p) => isObject(p) && isString(p.name) && isString(p.via) && VIAS.includes(p.via))
  );
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
  if (!isString(r.tool) || !isString(r.callId) || !isString(r.rid) || typeof r.now !== "number" || !isObject(r.input) || !isResolved(r.resolved)) {
    return "UNREADABLE";
  }
  if (!isString(r.verdict) || !VERDICTS.includes(r.verdict) || !(r.proof === null || isObject(r.proof))) {
    return "UNREADABLE";
  }
  if (typeof r.routeAllowed !== "boolean" || !(r.rulesHash === null || isString(r.rulesHash))) {
    return "UNREADABLE";
  }
  // The record holds values; the SDK reads tokens, so each is written as the token it would have been sent as.
  let chain: string;
  let influence: string;
  let proof: string | null;
  try {
    chain = writeToken(r.chain as JsonValue);
    influence = writeToken(r.influence as JsonValue);
    proof = r.proof === null ? null : writeToken(r.proof as JsonValue);
  } catch {
    return "UNREADABLE";
  }
  if (client === undefined) {
    return "NO_CLIENT";
  }
  const step = {
    tool: r.tool, callId: r.callId, rid: r.rid, now: r.now, input: r.input, resolved: r.resolved, verdict: r.verdict as LocalVerdict,
    routeAllowed: r.routeAllowed, rulesHash: r.rulesHash, chain, proof, influence,
  };
  const run = runOf(r.rid);
  const v = verifyRecordedLocalStep(step, { client, signers: SIGNERS, ...(run !== undefined ? { run } : {}), seen });
  if (v.reason !== "OK") {
    return v.reason;
  }
  return v.verdict === "OK" ? "OK" : "REFUSED";
}
