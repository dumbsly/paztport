// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// One test per sentence of verification.md §Offline verification, "A recorded local step" (MCP profile).

import { describe, expect, it } from "vitest";
import { generateKeyPair, randomBytes } from "../../src/crypto/crypto.ts";
import { influenceBlock, type InfluenceEntry } from "../../src/influence/influence.ts";
import type { LocalVerdict, Resolved } from "../../src/local/local-decision.ts";
import { stampLocalStep } from "../../src/local/local-step.ts";
import { parseLocalRules, rulesHash, type LocalRules } from "../../src/policy/local-rules.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import { buildTree, type MerkleProof } from "../../src/policy/merkle.ts";
import { bindPrompt } from "../../src/stamp/binding.ts";
import { commitBlock, EMPTY_BLOCK, makeBlock, type Block } from "../../src/stamp/block.ts";
import { signStamp, type Stamp } from "../../src/stamp/stamp.ts";
import { verifyRecordedLocalStep, type LocalStepClient, type RecordedLocalStep } from "../../src/offline/local-step.ts";

const RUN_TS = 1_000;
const STEP_TS = 2_000;
const PROMPT = "tidy the notes";
const SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };
const RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }], programs: [] });
const READ: Resolved = { paths: [{ need: "read", at: "notes.md" }], programs: [], parse: "ok", readOnly: true };
const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };
const INFLUENCE: InfluenceEntry[] = [{ cls: "private", src: "file:notes.md", h: "h1" }];
/** The run's origin names `influence` with nothing to add; the client hop's block holds the session's influence. */
const ORIGIN_BLOCK = influenceBlock([]);

type Decision = { tool: string; callId: string; input: unknown; resolved: Resolved; verdict: LocalVerdict; routeAllowed: boolean; rulesHash: string | null };

/** The token of the decision a step records. */
function decisionToken(d: Omit<Decision, "tool" | "input">): string {
  const { callId, resolved, verdict, routeAllowed, rulesHash } = d;
  return writeToken({ callId, resolved, verdict, routeAllowed, rulesHash });
}

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
  const origin = (over: Partial<Omit<Stamp, "v" | "sig">> = {}) =>
    signStamp(
      {
        svc: "session", inst: "pi-1", rid: "rid-1", ts: RUN_TS, sess: "", rcv: "pi", bind: bindPrompt(PROMPT),
        ext: commitBlock(ORIGIN_BLOCK), prev: "", ...over,
      },
      session.privateKey,
    );
  /**
   * A step the gate signed for `d`, its proof the tree's for the tool's route when `routeAllowed`. `block` is the
   * client hop's block, the session's influence by default, and `blocks` the token recorded in place of the two signed.
   */
  type StepOver = {
    key?: string; ts?: number; proof?: MerkleProof | null; originOver?: Partial<Omit<Stamp, "v" | "sig">>;
    block?: Block; blocks?: string | null;
  };
  const step = (d: Partial<Decision> = {}, o: StepOver = {}): RecordedLocalStep => {
    const decision: Decision = { tool: "read", callId: "tc-1", input: { path: "notes.md" }, resolved: READ, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(RULES), ...d };
    const first = origin(o.originOver);
    const ts = o.ts ?? STEP_TS;
    const block = o.block ?? influenceBlock(INFLUENCE);
    const stamp = stampLocalStep(
      {
        svc: "pi", inst: "pi-1", rid: "rid-1", ts, prev: first.sig, toolName: decision.tool, toolCallId: decision.callId, input: decision.input,
        resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed,
        rulesHash: decision.rulesHash, block,
      },
      o.key ?? pi.privateKey,
    );
    const listed = decision.routeAllowed ? tree.proofFor(`session/pi/local:${decision.tool}`) : null;
    const proof = Object.hasOwn(o, "proof") ? o.proof! : listed;
    const { tool, input } = decision;
    return {
      tool, input, callId: decision.callId, decision: decisionToken(decision), rid: "rid-1", now: ts,
      chain: writeToken([first, stamp]),
      proof: proof === null ? null : writeToken(proof),
      blocks: Object.hasOwn(o, "blocks") ? o.blocks! : writeToken([ORIGIN_BLOCK, block] as unknown as JsonValue),
    };
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

  for (const tool of ["ext/bash", ".", ".."]) {
    it(`anUnlistedToolNamed${JSON.stringify(tool)}IsStampedAndItsRefusalVerifies`, () => {
      // the tool is data in `local:<tool>`, and an unlisted tool's route is never proven, so no route-node rule applies
      const w = world();
      expect(w.check(w.step({ tool, input: {}, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }))).toEqual({
        reason: "OK",
        verdict: "PATH_NOT_ALLOWED",
      });
    });
  }

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

  // "nonceKey = JCS([rid, callId, "local"])"
  it("theNonceKeyIsSpentInTheRecordSet", () => {
    const w = world();
    const seen = new Set<string>();
    expect(w.check(w.step(), w.client(), seen).reason).toBe("OK");
    expect([...seen]).toEqual(['["rid-1","tc-1","local"]']);
    expect(w.check(w.step(), w.client(), seen).reason).toBe("REPLAY");
    expect(w.check(w.step({ callId: "tc-2" }), w.client(), seen).reason).toBe("OK");
  });

  it("theStepBindsItsDecision", () => {
    const w = world();
    expect(w.check({ ...w.step(), input: { path: "secret.md" } }).reason).toBe("BINDING_MISMATCH");
    const signed = w.step();
    const other = decisionToken({
      callId: "tc-1", resolved: READ, verdict: "SCOPE_DENIED", routeAllowed: true, rulesHash: rulesHash(RULES),
    });
    expect(w.check({ ...signed, decision: other }).reason).toBe("BINDING_MISMATCH");
    expect(w.check({ ...w.step(), tool: "re\nad" }).reason).toBe("BINDING_MISMATCH");
  });

  it("aDecisionThatDoesNotReadIsBindingMismatch", () => {
    const w = world();
    const signed = w.step();
    expect(w.check({ ...signed, decision: "not*base64url" }).reason).toBe("BINDING_MISMATCH");
    expect(w.check({ ...signed, decision: writeToken([1]) }).reason).toBe("BINDING_MISMATCH");
    const unknownVerdict = writeToken({
      callId: "tc-1", resolved: READ, verdict: "MAYBE", routeAllowed: true, rulesHash: null,
    });
    expect(w.check({ ...signed, decision: unknownVerdict }).reason).toBe("BINDING_MISMATCH");
  });

  it("aDecisionForAnotherCallIsBindingMismatch", () => {
    const w = world();
    const other = w.step({ callId: "tc-2" });
    expect(w.check({ ...w.step(), decision: other.decision }).reason).toBe("BINDING_MISMATCH");
  });

  it("aDecisionWithAnExtraMemberIsBindingMismatch", () => {
    const w = world();
    const d = {
      callId: "tc-1", resolved: READ, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(RULES), note: "x",
    };
    expect(w.check({ ...w.step(), decision: writeToken(d) }).reason).toBe("BINDING_MISMATCH");
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

  // "each limit not configured is its live default": the step within the run's lifetime of its origin, the origin
  // not more than the call window after it
  it("aStepMoreThanThirtyMinutesIntoItsRunIsExpired", () => {
    const w = world();
    const at = (originTs: number, stepTs: number, limits: { runMaxAgeMs?: number; callMaxAgeMs?: number } = {}) => {
      const s = w.step({}, { ts: stepTs, originOver: { ts: originTs } });
      return verifyRecordedLocalStep(s, { client: w.client(), signers: SIGNERS, run: { prompt: PROMPT, ts: new Set([originTs]) }, seen: new Set(), ...limits }).reason;
    };
    expect(at(RUN_TS, RUN_TS + 1_800_000)).toBe("OK");
    expect(at(RUN_TS, RUN_TS + 1_800_001)).toBe("EXPIRED");
    expect(at(RUN_TS + 5_000, RUN_TS)).toBe("OK");
    expect(at(RUN_TS + 5_001, RUN_TS)).toBe("EXPIRED");
    // configured limits replace the defaults, each on its own
    expect(at(RUN_TS, RUN_TS + 1_800_001, { runMaxAgeMs: 1_800_001 })).toBe("OK");
    expect(at(RUN_TS + 5_001, RUN_TS, { callMaxAgeMs: 5_001 })).toBe("OK");
    expect(at(RUN_TS, RUN_TS + 11, { runMaxAgeMs: 10 })).toBe("EXPIRED");
  });

  // "A record carries the token of its chain's blocks beside the chain, and a recorded local step's stamp commits to
  // its block like any other stamp."
  it("aStepVerifiesWithItsBlocksToken", () => {
    const w = world();
    expect(w.check(w.step()).reason).toBe("OK");
    // no token is every block empty, which reads only when the stamps committed to nothing
    expect(w.check(w.step({}, { blocks: null })).reason).toBe("EXTENSION_MISMATCH");
    const silent = w.step({}, { originOver: { ext: "" }, block: EMPTY_BLOCK, blocks: null });
    expect(w.check(silent)).toEqual({ reason: "OK", verdict: "OK" });
  });

  it("anAlteredBlockIsExtensionMismatch", () => {
    const w = world();
    const swapped = writeToken([ORIGIN_BLOCK, influenceBlock([{ cls: "public", src: "file:notes.md", h: "h1" }])] as
      unknown as JsonValue);
    expect(w.check(w.step({}, { blocks: swapped })).reason).toBe("EXTENSION_MISMATCH");
    expect(w.check(w.step({}, { blocks: writeToken([ORIGIN_BLOCK] as unknown as JsonValue) })).reason)
      .toBe("EXTENSION_MISMATCH");
    expect(w.check(w.step({}, { blocks: "not*base64url" })).reason).toBe("EXTENSION_MISMATCH");
  });

  // "Then the extension's reading of the items in the step's blocks: an item under influence that does not read is
  // INFLUENCE_MISMATCH." Then, at the step's ts, POLICY_EXPIRED.
  it("anItemUnderInfluenceThatIsNotAnEntryIsInfluenceMismatch", () => {
    const w = world();
    const block = makeBlock({ influence: [{ cls: "third-party", src: "web:example.com" }] });
    expect(w.check(w.step({}, { block })).reason).toBe("INFLUENCE_MISMATCH");
    expect(w.check(w.step({}, { block }), w.client({ rootNotAfter: STEP_TS - 1 })).reason).toBe("INFLUENCE_MISMATCH");
    // an unlisted tool's refusal goes on past the chain check, and so is read too
    const refusal = {
      tool: "bash", input: {}, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false,
    } as const;
    const unlisted = w.step(refusal, { block });
    expect(w.check(unlisted).reason).toBe("INFLUENCE_MISMATCH");
    // only items under influence are read
    expect(w.check(w.step({}, { block: makeBlock({ example: ["x"] }) }))).toEqual({ reason: "OK", verdict: "OK" });
  });

  it("theVerdictIsReDerivedFromTheClassesOfTheEntriesInTheBlocks", () => {
    const w = world();
    const publicSite = parseLocalRules({
      v: 1,
      folders: [{ path: ".", access: ["read"] }, { path: "website", access: ["read", "write"], destination: "public" }],
      programs: [],
    });
    const c = w.client({ rules: publicSite });
    const write: Resolved = {
      paths: [{ need: "write", at: "website/a.md" }], programs: [], parse: "ok", readOnly: false,
    };
    const d = { tool: "write", input: { path: "website/a.md" }, resolved: write, rulesHash: rulesHash(publicSite) };
    const steered = influenceBlock([...INFLUENCE, { cls: "third-party", src: "server:github", h: "h2" }]);
    expect(w.check(w.step({ ...d, verdict: "INFLUENCE_DENIED" }, { block: steered }), c))
      .toEqual({ reason: "OK", verdict: "INFLUENCE_DENIED" });
    expect(w.check(w.step({ ...d, verdict: "OK" }, { block: steered }), c).reason).toBe("VERDICT_MISMATCH");
    // the origin's entries count as the client hop's do
    const fromOrigin = { originOver: { ext: commitBlock(steered) }, block: influenceBlock([]) };
    const both = writeToken([steered, influenceBlock([])] as unknown as JsonValue);
    expect(w.check(w.step({ ...d, verdict: "INFLUENCE_DENIED" }, { ...fromOrigin, blocks: both }), c))
      .toEqual({ reason: "OK", verdict: "INFLUENCE_DENIED" });
    // with only the private entry, the write is allowed, and a refusal is not what the rules give
    expect(w.check(w.step({ ...d, verdict: "OK" }), c)).toEqual({ reason: "OK", verdict: "OK" });
    expect(w.check(w.step({ ...d, verdict: "INFLUENCE_DENIED" }), c).reason).toBe("VERDICT_MISMATCH");
  });

  it("aRidOrCallIdNoKeyCanBeFormedFromGivesTheChainChecksResultAndDoesNotThrow", () => {
    const w = world();
    for (const rid of ["rid-1\ud800", "rid-1\ufdd0", "rid-1\uffff"]) {
      const seen = new Set<string>();
      expect(w.check({ ...w.step(), rid }, w.client(), seen).reason, JSON.stringify(rid)).toBe("RID_MISMATCH");
      expect(seen.size).toBe(0);
    }
    // an earlier check of the chain still comes first
    expect(w.check({ ...w.step({}, { key: w.session.privateKey }), rid: "rid-1\ud800" }).reason).toBe("BAD_SIGNATURE");
    for (const callId of ["tc-1\ud800", "tc-1\ufdd0"]) {
      expect(w.check({ ...w.step(), callId }).reason, JSON.stringify(callId)).toBe("BINDING_MISMATCH");
    }
  });
});
