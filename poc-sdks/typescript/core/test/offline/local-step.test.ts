// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// One test per sentence of verification.md §Offline verification, "A recorded local step" (MCP profile).

import { describe, expect, it } from "vitest";
import { generateKeyPair, randomBytes } from "../../src/crypto/crypto.ts";
import { commitInfluence, type InfluenceEntry } from "../../src/influence/influence.ts";
import type { LocalVerdict, Resolved } from "../../src/influence/local-decision.ts";
import { localStepBind, stampLocalStep } from "../../src/influence/local-step.ts";
import { parseLocalRules, rulesHash, type LocalRules } from "../../src/policy/local-rules.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { buildTree, type MerkleProof } from "../../src/policy/merkle.ts";
import { bindPrompt } from "../../src/stamp/binding.ts";
import { signStampV3, type StampV3 } from "../../src/stamp/stamp.ts";
import { verifyRecordedLocalStep, type LocalStepClient, type RecordedLocalStep } from "../../src/offline/local-step.ts";

const RUN_TS = 1_000;
const STEP_TS = 2_000;
const PROMPT = "tidy the notes";
const SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };
const RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }], programs: [] });
const READ: Resolved = { paths: [{ need: "read", at: "notes.md" }], programs: [], parse: "ok", readOnly: true };
const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };
const INFLUENCE: InfluenceEntry[] = [{ cls: "private", src: "file:notes.md", h: "h1" }];

type Decision = { tool: string; callId: string; input: unknown; resolved: Resolved; verdict: LocalVerdict; routeAllowed: boolean; rulesHash: string | null };

function world() {
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const tree = buildTree(["session/pi/local:read", "session/pi/local:write"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const client = (over: Partial<LocalStepClient> = {}): LocalStepClient => ({
    keyring: { session: session.publicKey, pi: pi.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    rootNotAfter: Number.MAX_SAFE_INTEGER,
    keyringNotAfter: Number.MAX_SAFE_INTEGER,
    rules: RULES,
    ...over,
  });
  const origin = (over: Partial<Omit<StampV3, "v" | "sig">> = {}) =>
    signStampV3({ svc: "session", inst: "pi-1", rid: "rid-1", ts: RUN_TS, sess: "", rcv: "pi", bind: bindPrompt(PROMPT), infl: "", prev: "", ...over }, session.privateKey);
  /** A step the gate signed for `d`, its proof the tree's for the tool's route when `routeAllowed`. */
  const step = (d: Partial<Decision> = {}, o: { key?: string; ts?: number; proof?: MerkleProof | null; originOver?: Partial<Omit<StampV3, "v" | "sig">> } = {}): RecordedLocalStep => {
    const decision: Decision = { tool: "read", callId: "tc-1", input: { path: "notes.md" }, resolved: READ, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(RULES), ...d };
    const first = origin(o.originOver);
    const ts = o.ts ?? STEP_TS;
    const stamp = stampLocalStep(
      {
        svc: "pi", inst: "pi-1", rid: "rid-1", ts, prev: first.sig, toolName: decision.tool, toolCallId: decision.callId, input: decision.input,
        resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash, influence: INFLUENCE,
      },
      o.key ?? pi.privateKey,
    );
    const proof = Object.hasOwn(o, "proof") ? o.proof! : decision.routeAllowed ? tree.proofFor(`session/pi/local:${decision.tool}`) : null;
    return { ...decision, rid: "rid-1", now: ts, chain: writeToken([first, stamp]), proof: proof === null ? null : writeToken(proof), influence: writeToken(INFLUENCE) };
  };
  const run = { prompt: PROMPT, ts: new Set([RUN_TS]) };
  const check = (s: RecordedLocalStep, c: LocalStepClient = client(), seen = new Set<string>()) => verifyRecordedLocalStep(s, { client: c, signers: SIGNERS, run, seen });
  return { session, pi, tree, client, origin, step, run, check };
}

describe("verifyRecordedLocalStep", () => {
  it("anAllowedStepVerifies", () => {
    const w = world();
    expect(w.check(w.step())).toEqual({ reason: "OK", verdict: "OK" });
  });

  it("aRefusalTheRulesGiveVerifiesWithItsVerdict", () => {
    const w = world();
    const write: Resolved = { paths: [{ need: "write", at: "notes.md" }], programs: [], parse: "ok", readOnly: false };
    expect(w.check(w.step({ tool: "write", input: { path: "notes.md" }, resolved: write, verdict: "SCOPE_DENIED" }))).toEqual({ reason: "OK", verdict: "SCOPE_DENIED" });
  });

  it("anUnlistedToolsRefusalVerifies", () => {
    // its route is not proven: that is how the gate's PATH_NOT_ALLOWED verifies
    const w = world();
    expect(w.check(w.step({ tool: "bash", input: { command: "ls" }, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }))).toEqual({
      reason: "OK",
      verdict: "PATH_NOT_ALLOWED",
    });
  });

  it("withNoRulesEveryStepIsScopeDenied", () => {
    const w = world();
    const none = w.client({ rules: null });
    expect(w.check(w.step({ resolved: NOTHING, verdict: "SCOPE_DENIED", rulesHash: null }), none)).toEqual({ reason: "OK", verdict: "SCOPE_DENIED" });
    expect(w.check(w.step({ rulesHash: null }), none).reason).toBe("VERDICT_MISMATCH");
  });

  // "the offline chain verifier with signers (the origin service then the client hop, both on the client's one instance)"
  it("theChainIsCheckedWithTheSignersGiven", () => {
    const w = world();
    expect(w.check(w.step({}, { originOver: { inst: "pi-2" } })).reason).toBe("BAD_ORIGIN");
    expect(w.check(w.step({}, { key: w.session.privateKey })).reason).toBe("BAD_SIGNATURE");
    const swapped = verifyRecordedLocalStep(w.step(), { client: w.client(), signers: { svcs: ["session", "gateway"], inst: "pi-1" }, run: w.run, seen: new Set() });
    expect(swapped.reason).toBe("BAD_SIGNATURE");
  });

  // "sess = """
  it("aStepInASessionIsSessionUnknown", () => {
    const w = world();
    expect(w.check(w.step({}, { originOver: { sess: "sess-1" } })).reason).toBe("SESSION_UNKNOWN");
  });

  // "the client's root and keyring"
  it("theStepIsCheckedAgainstTheClientsRootAndKeyring", () => {
    const w = world();
    const other = buildTree(["session/pi/local:read"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
    expect(w.check(w.step(), w.client({ root: other.root, rootId: other.rootId })).reason).toBe("PROOF_MISMATCH");
    expect(w.check(w.step(), w.client({ keyring: { session: w.session.publicKey, pi: generateKeyPair().publicKey } })).reason).toBe("BAD_SIGNATURE");
  });

  // "nonceKey = <rid>|<callId>|local"
  it("theNonceKeyIsSpentInTheRecordSet", () => {
    const w = world();
    const seen = new Set<string>();
    expect(w.check(w.step(), w.client(), seen).reason).toBe("OK");
    expect([...seen]).toEqual(["rid-1|tc-1|local"]);
    expect(w.check(w.step(), w.client(), seen).reason).toBe("REPLAY");
    expect(w.check(w.step({ callId: "tc-2" }), w.client(), seen).reason).toBe("OK");
  });

  it("theStepBindsItsDecision", () => {
    const w = world();
    expect(w.check({ ...w.step(), input: { path: "secret.md" } }).reason).toBe("BINDING_MISMATCH");
    expect(w.check({ ...w.step(), verdict: "SCOPE_DENIED" }).reason).toBe("BINDING_MISMATCH");
    expect(w.check({ ...w.step(), tool: "re\nad" }).reason).toBe("BINDING_MISMATCH");
  });

  // "Then, at the step's ts, the client's root and keyring are no later than their notAfter (POLICY_EXPIRED)."
  it("aStepPastTheClientsRootOrKeyringIsPolicyExpired", () => {
    const w = world();
    expect(w.check(w.step(), w.client({ rootNotAfter: STEP_TS })).reason).toBe("OK");
    expect(w.check(w.step(), w.client({ rootNotAfter: STEP_TS - 1 })).reason).toBe("POLICY_EXPIRED");
    expect(w.check(w.step(), w.client({ keyringNotAfter: STEP_TS })).reason).toBe("OK");
    expect(w.check(w.step(), w.client({ keyringNotAfter: STEP_TS - 1 })).reason).toBe("POLICY_EXPIRED");
  });

  it("policyExpiredComesAfterTheChainAndBeforeTheProof", () => {
    const w = world();
    expect(w.check(w.step({}, { key: w.session.privateKey }), w.client({ rootNotAfter: 0 })).reason).toBe("BAD_SIGNATURE");
    expect(w.check(w.step({ routeAllowed: false }), w.client({ rootNotAfter: 0 })).reason).toBe("POLICY_EXPIRED");
  });

  // "Then the route verdict and proof the client recorded for the step MUST be what its chain proves (PROOF_MISMATCH)"
  it("aRouteVerdictOrProofTheChainDoesNotProveIsProofMismatch", () => {
    const w = world();
    // listed, but the proof recorded does not prove the route
    expect(w.check(w.step({}, { proof: null })).reason).toBe("PROOF_MISMATCH");
    expect(w.check(w.step({}, { proof: w.tree.proofFor("session/pi/local:write") })).reason).toBe("PROOF_MISMATCH");
    // proven, but recorded as not listed
    expect(w.check(w.step({ resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }, { proof: w.tree.proofFor("session/pi/local:read") })).reason).toBe(
      "PROOF_MISMATCH",
    );
    // not listed and not proven, but carrying a proof
    expect(
      w.check(w.step({ tool: "bash", input: {}, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }, { proof: w.tree.proofFor("session/pi/local:read") })).reason,
    ).toBe("PROOF_MISMATCH");
  });

  // "the rulesHash the step signed MUST be the client's (RULES_MISMATCH)"
  it("aSignedRulesHashThatIsNotTheClientsIsRulesMismatch", () => {
    const w = world();
    const other = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }, { path: "out", access: ["write"], destination: "public" }], programs: [] });
    expect(w.check(w.step({ rulesHash: rulesHash(other) })).reason).toBe("RULES_MISMATCH");
    expect(w.check(w.step({ rulesHash: null })).reason).toBe("RULES_MISMATCH");
    expect(w.check(w.step(), w.client({ rules: other })).reason).toBe("RULES_MISMATCH");
  });

  // "and the decision it signed MUST be the one re-derived from those signed rules (VERDICT_MISMATCH)"
  it("aDecisionTheSignedRulesDoNotGiveIsVerdictMismatch", () => {
    const w = world();
    const write: Resolved = { paths: [{ need: "write", at: "notes.md" }], programs: [], parse: "ok", readOnly: false };
    expect(w.check(w.step({ tool: "write", resolved: write, verdict: "OK" })).reason).toBe("VERDICT_MISMATCH");
    expect(w.check(w.step({ verdict: "SCOPE_DENIED" })).reason).toBe("VERDICT_MISMATCH");
    // an unlisted tool resolves nothing
    expect(w.check(w.step({ tool: "bash", input: {}, resolved: READ, verdict: "PATH_NOT_ALLOWED", routeAllowed: false })).reason).toBe("VERDICT_MISMATCH");
  });

  it("theFirstFailureIsTheResult", () => {
    const w = world();
    expect(w.check(w.step({ rulesHash: null }, { proof: null })).reason).toBe("PROOF_MISMATCH");
    expect(w.check(w.step({ rulesHash: null, verdict: "SCOPE_DENIED" })).reason).toBe("RULES_MISMATCH");
  });

  it("theRunsTimesAndPromptAreChecked", () => {
    const w = world();
    expect(w.check({ ...w.step(), now: STEP_TS + 1 }).reason).toBe("TIME_MISMATCH");
    expect(verifyRecordedLocalStep(w.step(), { client: w.client(), signers: SIGNERS, run: { prompt: PROMPT, ts: new Set([RUN_TS + 1]) }, seen: new Set() }).reason).toBe("TIME_MISMATCH");
    expect(verifyRecordedLocalStep(w.step(), { client: w.client(), signers: SIGNERS, run: { prompt: "another", ts: new Set([RUN_TS]) }, seen: new Set() }).reason).toBe("PROMPT_MISMATCH");
    expect(verifyRecordedLocalStep(w.step(), { client: w.client(), signers: SIGNERS, seen: new Set() }).reason).toBe("PROMPT_MISMATCH");
  });
});
