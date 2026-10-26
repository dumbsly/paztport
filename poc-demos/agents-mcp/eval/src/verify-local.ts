// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindLocalTool,
  bindPrompt,
  canonicalize,
  commitInfluence,
  decode,
  influenceClasses,
  parseInfluence,
  parseLocalRules,
  parseProof,
  parseStampsV2,
  RULES_ROUTE_PREFIX,
  rulesHash,
  signingBytesV2,
  verify,
  verifyProof,
  verifyRoot,
  type InfluenceEntry,
  type LocalRules,
  type ReasonCode,
  type StampV2,
} from "@paztport/path-attest";
import { decideLocal, type LocalVerdict, type Resolved } from "../../pi-extension/src/local/decide.ts";

/**
 * Offline checks of the pi extension's local steps (phase 2), used by verify.ts. The extension writes a
 * `client` record (the client mesh: keyring, policy key, signed root, local rules and their proof) at session
 * start, and then one `local` record per gated built-in tool call.
 *
 * The client record verifies when its root verifies against its policy key, every session record in the file
 * that names a client root names this root with the same policy key and keyring, and, when it has rules, the
 * rules parse and `rulesProof` proves `session/pi/rules:<rulesHash(rules)>` against the root. With no rules,
 * `rulesProof` must be null. The client policy key is trusted on first use from the file, as it is in session
 * records (where the server's signed reply binds it); verify pins no client key of its own.
 *
 * A local record is checked against the latest client record before it, in this order (the first failure is
 * its result):
 * 1. its fields are well formed (UNREADABLE), there is a verified client record (NO_CLIENT), and its
 *    (rid, call id) is new in the file (REPLAY);
 * 2. the origin stamp is svc "session", inst "pi-1" (BAD_ORIGIN), the step stamp is svc "pi", inst "pi-1",
 *    and the keyring's session and pi keys sign them (BAD_SIGNATURE); a step signature already seen in the
 *    file (the same signed step under another call id or rid) is REPLAY;
 * 3. the step follows the origin (BROKEN_LINK), both carry the record's rid (RID_MISMATCH) and an empty
 *    `sess` (SESSION_UNKNOWN);
 * 4. the step's time is the record's `now`, and the origin's time is the time of a run record for the rid
 *    (TIME_MISMATCH); the origin binds that run's prompt (PROMPT_MISMATCH);
 * 5. the step binds bindLocalTool(tool, input, { callId, resolved, verdict, routeAllowed, rulesHash }), so
 *    the call id and the decision are signed as well as the call (BINDING_MISMATCH), and commits to the recorded influence
 *    (INFLUENCE_MISMATCH);
 * 6. `routeAllowed` is true exactly when there is a proof, and the proof proves `session/pi/local:<tool>`
 *    against the client root (BAD_PROOF); `rulesHash` is the client record's rules hash, or null when it has
 *    no rules (RULES_MISMATCH);
 * 7. with the route not listed or no rules the gate resolves nothing, so `resolved` must be empty; and the
 *    verdict must be what the extension's own rule (decideLocal) gives for the recorded resolution and
 *    influence under the signed rules, or SCOPE_DENIED with no rules (VERDICT_MISMATCH).
 * A verified step is OK when it was allowed and REFUSED when it was refused: local refusals are signed and
 * checked, unlike the server's.
 *
 * Verify does not look at the disk: it checks that the rules were applied correctly to what the gate saw, not
 * that the gate saw the disk correctly. Freshness windows do not apply to local steps: they never cross a
 * boundary, so there is no receiver whose clock they must fit.
 */
export type LocalResult =
  | "OK"
  | "REFUSED"
  | "UNREADABLE"
  | "PROMPT_MISMATCH"
  | ReasonCode
  | "BAD_CLIENT"
  | "NO_CLIENT"
  | "BAD_PROOF"
  | "TIME_MISMATCH"
  | "RULES_MISMATCH"
  | "VERDICT_MISMATCH";

/** What a verified client record gives the local records that follow it. */
export type Client = { keyring: Record<string, string>; root: Uint8Array; rootId: string; rules: LocalRules | null; rulesHash: string | null };

/** A client root, policy key and keyring that a session record in the file names. */
export type NamedClient = { root: unknown; policyKey: unknown; keyring: unknown };

/** A rid's run: its undisputed prompt and the times its run records give. */
export type RunInfo = { prompt: string; ts: ReadonlySet<number> };

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";

const LOCAL_ROUTE_PREFIX = "session/pi/local:";
const INST = "pi-1";
const VERDICTS: readonly string[] = ["OK", "PATH_NOT_ALLOWED", "SCOPE_DENIED", "UNCHECKABLE", "INFLUENCE_DENIED"] satisfies LocalVerdict[];
const NEEDS: readonly string[] = ["read", "write", "exec"];
const VIAS: readonly string[] = ["list", "folder", "never", "missing", "uncheckable"];
/** What the gate records when it resolves nothing. */
const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };

/** The verified client record, or undefined when it does not verify (see the module comment). */
export function verifyClient(r: Rec, named: NamedClient[]): Client | undefined {
  try {
    const sr = r.signedRoot;
    const keyring = r.keyring;
    if (!isObject(keyring) || !Object.values(keyring).every(isString) || !isString(r.policyPublicKey)) {
      return undefined;
    }
    if (!isObject(sr) || !isString(sr.rootId) || !isString(sr.root) || !isString(sr.sig)) {
      return undefined;
    }
    const signedRoot = { rootId: sr.rootId, root: sr.root, sig: sr.sig };
    if (!verifyRoot(signedRoot, r.policyPublicKey)) {
      return undefined;
    }
    // the session's request is bound by the server's signed reply: a client record must agree with it
    for (const n of named) {
      if (canonicalize(n.root) !== canonicalize(signedRoot) || n.policyKey !== r.policyPublicKey || canonicalize(n.keyring) !== canonicalize(keyring)) {
        return undefined;
      }
    }
    const root = decode(signedRoot.root);
    let rules: LocalRules | null = null;
    let hash: string | null = null;
    if (r.rules !== null) {
      rules = parseLocalRules(r.rules); // throws on rules that don't parse
      hash = rulesHash(rules);
      const proof = parseProof(r.rulesProof);
      if (proof.rootId !== signedRoot.rootId || !verifyProof(proof, `session/pi/${RULES_ROUTE_PREFIX}${hash}`, root)) {
        return undefined;
      }
    } else if (r.rulesProof !== null) {
      return undefined;
    }
    return { keyring: keyring as Record<string, string>, root, rootId: signedRoot.rootId, rules, rulesHash: hash };
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

function stampSigned(keyring: Record<string, string>, s: StampV2): boolean {
  try {
    return Object.hasOwn(keyring, s.svc) && verify(keyring[s.svc]!, signingBytesV2(s), decode(s.sig));
  } catch {
    return false;
  }
}

/**
 * What a file's local records have used so far: (rid, call id) pairs, and the signatures of verified step stamps.
 * One per file.
 */
export type LocalSeen = { calls: Set<string>; steps: Set<string> };

/**
 * Checks one local record (see the module comment). `seen` is the file's LocalSeen, updated here; `runOf` gives
 * a rid's run, or undefined when it has none or its prompt is in dispute.
 */
export function verifyLocal(r: Rec, client: Client | undefined, runOf: (rid: string) => RunInfo | undefined, seen: LocalSeen): LocalResult {
  if (!isString(r.tool) || !isString(r.callId) || !isString(r.rid) || typeof r.now !== "number" || !isObject(r.input) || !isResolved(r.resolved)) {
    return "UNREADABLE";
  }
  if (!isString(r.verdict) || !VERDICTS.includes(r.verdict) || !(r.proof === null || isObject(r.proof))) {
    return "UNREADABLE";
  }
  if (typeof r.routeAllowed !== "boolean" || !(r.rulesHash === null || isString(r.rulesHash))) {
    return "UNREADABLE";
  }
  let chain: StampV2[];
  let influence: InfluenceEntry[];
  try {
    chain = parseStampsV2(r.chain);
    influence = parseInfluence(r.influence);
  } catch {
    return "UNREADABLE";
  }
  if (chain.length !== 2) {
    return "UNREADABLE";
  }
  if (client === undefined) {
    return "NO_CLIENT";
  }
  const k = JSON.stringify([r.rid, r.callId]);
  if (seen.calls.has(k)) {
    return "REPLAY";
  }
  seen.calls.add(k);
  const [origin, step] = chain as [StampV2, StampV2];
  if (origin.svc !== "session" || origin.inst !== INST) {
    return "BAD_ORIGIN";
  }
  if (step.svc !== "pi" || step.inst !== INST || !stampSigned(client.keyring, origin) || !stampSigned(client.keyring, step)) {
    return "BAD_SIGNATURE";
  }
  // the same signed step again, under another call id or rid
  if (seen.steps.has(step.sig)) {
    return "REPLAY";
  }
  seen.steps.add(step.sig);
  if (origin.prev !== "" || step.prev !== origin.sig) {
    return "BROKEN_LINK";
  }
  if (origin.rid !== r.rid || step.rid !== r.rid) {
    return "RID_MISMATCH";
  }
  if (origin.sess !== "" || step.sess !== "") {
    return "SESSION_UNKNOWN";
  }
  const run = runOf(r.rid);
  if (step.ts !== r.now || (run !== undefined && !run.ts.has(origin.ts))) {
    return "TIME_MISMATCH";
  }
  if (run === undefined || origin.bind !== bindPrompt(run.prompt)) {
    return "PROMPT_MISMATCH";
  }
  const verdict = r.verdict as LocalVerdict;
  let bind: string;
  try {
    bind = bindLocalTool(r.tool, r.input, { callId: r.callId, resolved: r.resolved, verdict, routeAllowed: r.routeAllowed, rulesHash: r.rulesHash });
  } catch {
    return "BINDING_MISMATCH";
  }
  if (step.bind !== bind) {
    return "BINDING_MISMATCH";
  }
  if (step.infl !== commitInfluence(influence)) {
    return "INFLUENCE_MISMATCH";
  }
  if (r.routeAllowed !== (r.proof !== null)) {
    return "BAD_PROOF";
  }
  if (r.proof !== null) {
    try {
      const proof = parseProof(r.proof);
      if (proof.rootId !== client.rootId || !verifyProof(proof, LOCAL_ROUTE_PREFIX + r.tool, client.root)) {
        return "BAD_PROOF";
      }
    } catch {
      return "BAD_PROOF";
    }
  }
  if (r.rulesHash !== client.rulesHash) {
    return "RULES_MISMATCH";
  }
  // with the route not listed or no rules, the gate resolves nothing
  if ((!r.routeAllowed || client.rules === null) && canonicalize(r.resolved) !== canonicalize(NOTHING)) {
    return "VERDICT_MISMATCH";
  }
  // no rules: the gate refuses every call as out of scope, and decideLocal has nothing to apply
  const expected: LocalVerdict =
    client.rules === null ? "SCOPE_DENIED" : decideLocal({ routeAllowed: r.routeAllowed, resolved: r.resolved, rules: client.rules, classes: influenceClasses(influence) });
  if (expected !== verdict) {
    return "VERDICT_MISMATCH";
  }
  return verdict === "OK" ? "OK" : "REFUSED";
}
