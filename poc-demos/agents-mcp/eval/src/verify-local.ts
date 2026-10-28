// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  canonicalize,
  decideLocalCall,
  decode,
  influenceClasses,
  localReceiver,
  localStepBind,
  ORIGIN_SVC,
  parseInfluence,
  parseLocalRules,
  parseRecordedStamps,
  parseSignedRoot,
  provesPath,
  readNotAfter,
  rulesHash,
  rulesRoute,
  verifyChainOffline,
  verifyKeyring,
  verifyRoot,
  type InfluenceEntry,
  type LocalRules,
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
 * `rulesProof` must be null. A `keyringSig` must be the policy key's signature over the keyring, over
 * `keyringNotAfter` too when the record has one; a record from before keyrings were signed has none, and is
 * accepted without it. The root is checked whole, in its own form; a window, the root's or the keyring's, that is
 * present but not an integer in [0, 2^53 − 1] fails the record. Each session record must name the same root,
 * policy key and keyring, and, for a signed keyring, the same window. The client policy key is trusted on first
 * use from the file, as it is in session records (where the server's signed reply binds it); verify pins no
 * client key of its own.
 *
 * A local record is checked against the latest client record before it, in this order (the first failure is
 * its result):
 * 1. its fields are well formed, and its chain is an origin and a step (UNREADABLE); there is a verified client
 *    record (NO_CLIENT); the step's binding can be computed (BINDING_MISMATCH);
 * 2. the chain, by verifyChainOffline in the library's order: the origin is svc "session", inst "pi-1"
 *    (BAD_ORIGIN), the step is svc "pi", inst "pi-1", and the keyring's session and pi keys sign them
 *    (BAD_SIGNATURE), the step follows the origin (BROKEN_LINK), both carry the record's rid (RID_MISMATCH) and
 *    an empty `sess` (SESSION_UNKNOWN); the step's time is the record's `now`, and the origin's time is the time
 *    of a run record for the rid (TIME_MISMATCH); the origin binds that run's prompt (PROMPT_MISMATCH); the step
 *    binds localStepBind (the call, its id and the decision: what was resolved, the verdict, routeAllowed and
 *    rulesHash), so none of them can be changed after signing (BINDING_MISMATCH), and commits to the recorded
 *    influence (INFLUENCE_MISMATCH); its (rid, call id) is new in the file (REPLAY); and the route
 *    `session/pi/local:<tool>` is proven against the client root, or not;
 * 3. `routeAllowed` is true exactly when the route is proven, and a route that is not has no proof (BAD_PROOF);
 *    `rulesHash` is the client record's rules hash, or null when it has no rules (RULES_MISMATCH);
 * 4. `resolved` and the verdict are what the gate's own rule (decideLocalCall) gives for the recorded
 *    resolution and influence under the signed rules: with the route not listed or no rules nothing is
 *    resolved, and with no rules every call is SCOPE_DENIED (VERDICT_MISMATCH).
 * A verified step is OK when it was allowed and REFUSED when it was refused: local refusals are signed and
 * checked, unlike the server's. A chain is v3, its stamps naming pi and then `local:<tool>` as their receivers
 * (BINDING_MISMATCH), or one recorded before stamps named a receiver, all v2, which is legacy.
 *
 * Verify does not look at the disk: it checks that the rules were applied correctly to what the gate saw, not
 * that the gate saw the disk correctly. Freshness windows do not apply offline: a local step is checked against
 * the times recorded with it.
 */
export type LocalResult =
  | "OK"
  | "REFUSED"
  | "UNREADABLE"
  | ReasonCode
  | "BAD_CLIENT"
  | "NO_CLIENT"
  | "BAD_PROOF"
  | "RULES_MISMATCH"
  | "VERDICT_MISMATCH";

/** What a verified client record gives the local records that follow it. */
export type Client = { keyring: Record<string, string>; root: Uint8Array; rootId: string; rules: LocalRules | null; rulesHash: string | null };

/** A client root, policy key, keyring and keyring window that a session record in the file names. */
export type NamedClient = { root: unknown; policyKey: unknown; keyring: unknown; keyringNotAfter: unknown };

/** A rid's run: its undisputed prompt and the times its run records give. */
export type RunInfo = { prompt: string; ts: ReadonlySet<number> };

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";

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
    if (r.keyringSig === undefined && keyringNotAfter !== undefined) {
      return undefined;
    }
    const ring = { policy: r.policyPublicKey, services, sig: r.keyringSig as string };
    if (r.keyringSig !== undefined && !verifyKeyring(keyringNotAfter === undefined ? ring : { ...ring, notAfter: keyringNotAfter }, r.policyPublicKey)) {
      return undefined;
    }
    // the session's request is bound by the server's signed reply: a client record must agree with it
    for (const n of named) {
      if (
        canonicalize(n.root) !== canonicalize(signedRoot) ||
        n.policyKey !== r.policyPublicKey ||
        canonicalize(n.keyring) !== canonicalize(keyring) ||
        // a record from before keyrings were signed names no window to compare
        (r.keyringSig !== undefined && n.keyringNotAfter !== keyringNotAfter)
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
      if (!provesPath(r.rulesProof, rulesRoute(SIGNERS.svcs, hash), root, signedRoot.rootId)) {
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

/**
 * Checks one local record (see the module comment). `seen` is the file's set of spent nonce keys, shared with
 * its calls and updated here; `runOf` gives a rid's run, or undefined when it has none or its prompt is in dispute.
 * `legacy` is true when the record's chain parses as a legacy v2 one, and false when it is v3 or does not parse.
 */
export function verifyLocal(
  r: Rec,
  client: Client | undefined,
  runOf: (rid: string) => RunInfo | undefined,
  seen: Set<string>,
): { result: LocalResult; legacy: boolean } {
  let legacy = false;
  try {
    legacy = parseRecordedStamps(r.chain).legacy;
  } catch {
    // a chain that does not parse is not legacy, and checkLocal finds it UNREADABLE
  }
  return { result: checkLocal(r, client, runOf, seen), legacy };
}

function checkLocal(r: Rec, client: Client | undefined, runOf: (rid: string) => RunInfo | undefined, seen: Set<string>): LocalResult {
  if (!isString(r.tool) || !isString(r.callId) || !isString(r.rid) || typeof r.now !== "number" || !isObject(r.input) || !isResolved(r.resolved)) {
    return "UNREADABLE";
  }
  if (!isString(r.verdict) || !VERDICTS.includes(r.verdict) || !(r.proof === null || isObject(r.proof))) {
    return "UNREADABLE";
  }
  if (typeof r.routeAllowed !== "boolean" || !(r.rulesHash === null || isString(r.rulesHash))) {
    return "UNREADABLE";
  }
  let influence: InfluenceEntry[];
  try {
    influence = parseInfluence(r.influence);
    if (parseRecordedStamps(r.chain).stamps.length !== 2) {
      return "UNREADABLE";
    }
  } catch {
    return "UNREADABLE";
  }
  if (client === undefined) {
    return "NO_CLIENT";
  }
  const verdict = r.verdict as LocalVerdict;
  let bind: string;
  try {
    bind = localStepBind({ toolName: r.tool, toolCallId: r.callId, input: r.input, resolved: r.resolved, verdict, listed: r.routeAllowed, rulesHash: r.rulesHash });
  } catch {
    return "BINDING_MISMATCH";
  }
  const run = runOf(r.rid);
  const v = verifyChainOffline(
    {
      stamps: r.chain,
      expectedBind: bind,
      influence,
      proof: r.proof,
      receiver: localReceiver(r.tool),
      receiverInRoute: true,
      rid: r.rid,
      recordedTs: { last: r.now, ...(run !== undefined ? { run: run.ts } : {}) },
      ...(run !== undefined ? { prompt: run.prompt } : {}),
    },
    { keyring: client.keyring, root: client.root, rootId: client.rootId, allowedOrigins: [ORIGIN_SVC], sess: "", seen, nonceKey: `${r.rid}|${r.callId}|local`, signers: SIGNERS },
  );
  // an unproven route is how a refusal for an unlisted tool verifies; anything else is the record's failure
  if (v.reason !== "OK" && v.reason !== "PATH_NOT_ALLOWED") {
    return v.reason;
  }
  const proven = v.reason === "OK";
  if (proven !== r.routeAllowed || (!proven && r.proof !== null)) {
    return "BAD_PROOF";
  }
  if (r.rulesHash !== client.rulesHash) {
    return "RULES_MISMATCH";
  }
  // the gate's own rule, applied to what it recorded: with the route not listed or no rules it resolves nothing
  const resolved = r.resolved;
  const expected = decideLocalCall({ routeAllowed: r.routeAllowed, rules: client.rules, classes: influenceClasses(influence), resolve: () => resolved });
  if (canonicalize(expected.resolved) !== canonicalize(resolved) || expected.verdict !== verdict) {
    return "VERDICT_MISMATCH";
  }
  return verdict === "OK" ? "OK" : "REFUSED";
}
