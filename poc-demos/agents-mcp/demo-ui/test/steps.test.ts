// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { BUILTIN_SCENARIO_DIR, loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { buildTree, encode, makeBlock, randomBytes, readAttestation, readBlocks, readChain, readToken, utf8, writeToken, type JsonValue } from "@paztport/core";
import { buildSteps, finalAnswer, PLAIN_CLASS, PLAIN_REASON, PLAIN_RULE, plainReason } from "../src/steps.ts";

const scenario = loadScenario(BUILTIN_SCENARIO_DIR);
const RECORDED = join(import.meta.dirname, "fixtures/recorded-on-run");
const jsonl = (file: string) =>
  readFileSync(join(RECORDED, file), "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l));
/**
 * A scripted scenario-A run with Paztport on, in evidence format 2: the real eval, pi, extension and mock server, with
 * a stub in place of the model replaying the 19 tool calls of a run recorded with gemma4:26b-mlx on 2026-10-31. The
 * transcript has no thinking events and its final answer is "Done."; evidence holds the records as the extension wrote
 * them, each Paztport object as its token.
 */
const recorded = () => ({ transcript: jsonl("transcript.jsonl"), events: jsonl("events.jsonl"), outcome: jsonl("outcome.jsonl"), evidence: jsonl("evidence.jsonl") });

const start = (id: string, tool: string, args: Record<string, unknown>) => ({ type: "tool_execution_start", toolCallId: id, toolName: `mcp__github__${tool}`, args });
const toolcallEnd = (id: string, tool: string, args: Record<string, unknown>) => ({
  type: "message_update",
  assistantMessageEvent: { type: "toolcall_end", contentIndex: 0, toolCall: { type: "toolCall", id, name: `mcp__github__${tool}`, arguments: args } },
});
const classes = (over: Partial<Record<string, number>> = {}) => ({ "third-party": 0, private: 0, public: 0, "local-untrusted": 0, ...over });

function rec(over: Partial<OutcomeRecord> = {}): OutcomeRecord {
  return {
    ts: 1,
    mode: "enforce",
    tool: "list_issues",
    kind: "read",
    owner: "acme",
    repo: "website",
    publicDestination: false,
    privateRead: false,
    privateFileRead: false,
    isError: false,
    containsCanary: false,
    containsPrivateMarker: false,
    verdict: "ALLOWED",
    audit: false,
    ...over,
  };
}

/** The shape of a scenario-A run with Paztport on: list the issues, read a private file, try to write publicly. */
function attested() {
  const transcript = [
    { type: "session" },
    start("c1", "list_issues", { owner: "acme", repo: "website" }),
    toolcallEnd("c1", "list_issues", { owner: "acme", repo: "website" }),
    start("c2", "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
    start("c3", "create_branch", { owner: "acme", repo: "website", branch: "about-the-author" }),
  ];
  const events = [
    { ts: 1, type: "call", server: "github", tool: "list_issues", callId: "c1", rid: "r1", session: "attested" },
    { ts: 2, type: "response", server: "github", tool: "list_issues", callId: "c1", rid: "r1", verify: "OK", added: ["third-party"], isError: false, classes: classes({ "third-party": 1 }) },
    { ts: 3, type: "call", server: "github", tool: "get_file_contents", callId: "c2", rid: "r2", session: "attested" },
    { ts: 4, type: "response", server: "github", tool: "get_file_contents", callId: "c2", rid: "r2", verify: "OK", added: ["private"], isError: false, classes: classes({ "third-party": 1, private: 1 }) },
    { ts: 5, type: "call", server: "github", tool: "create_branch", callId: "c3", rid: "r3", session: "attested" },
    { ts: 6, type: "response", server: "github", tool: "create_branch", callId: "c3", rid: "r3", verdict: "INFLUENCE_DENIED", isError: true, classes: classes({ "third-party": 1, private: 1 }) },
  ];
  const outcome = [
    rec({ callId: "c1", rid: "r1", label: "third-party" }),
    rec({ callId: "c2", rid: "r2", tool: "get_file_contents", repo: "payroll-notes", label: "private", privateRead: true, privateFileRead: true }),
    rec({ callId: "c3", rid: "r3", tool: "create_branch", kind: "write", publicDestination: true, verdict: "INFLUENCE_DENIED" }),
  ];
  const evidence = [
    { v: 2, type: "call", server: "github", tool: "list_issues", callId: "c1", rid: "r1" },
    { v: 2, type: "response", server: "github", tool: "list_issues", callId: "c1", rid: "r1" },
    { v: 2, type: "call", server: "github", tool: "create_branch", callId: "c3", rid: "r3" },
  ];
  return { transcript, events, outcome, evidence };
}

describe("steps", () => {
  it("attestedRunSteps: list, private read, then a refused write with the plain reason", () => {
    const steps = buildSteps(scenario, attested());
    expect(steps.map((s) => s.tool)).toEqual(["list_issues", "get_file_contents", "create_branch"]);
    expect(steps.map((s) => s.result)).toEqual(["allowed", "allowed", "refused"]);
    expect(steps[2]!.reason).toBe("a public write after the agent had read private data together with text from someone outside the project or content from an unverified source");
    expect(steps[0]!.reason).toBeUndefined();
    expect(steps[2]!.evidence.callId).toBe("c3");
    expect(steps[2]!.evidence.rid).toBe("r3");
    expect(steps[2]!.evidence.outcome?.verdict).toBe("INFLUENCE_DENIED");
    expect(steps[2]!.evidence.events).toHaveLength(2);
    expect(steps[2]!.evidence.evidence).toHaveLength(1);
    expect(steps[1]!.evidence.evidence).toHaveLength(0);
  });

  it("attested held is the previous response's classes in plain words", () => {
    const steps = buildSteps(scenario, attested());
    expect(steps[0]!.held).toEqual([]);
    expect(steps[1]!.held).toEqual(["text written by someone outside the project"]);
    expect(steps[2]!.held).toEqual(["private data", "text written by someone outside the project"]);
  });

  it("offRunStepsByOrder: no call ids, records matched by order, held from earlier labels", () => {
    const transcript = [
      start("t1", "list_issues", { owner: "acme", repo: "website" }),
      start("t2", "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
      start("t3", "create_branch", { owner: "acme", repo: "website", branch: "b" }),
    ];
    const outcome = [
      rec({ mode: "off", label: "third-party" }),
      rec({ mode: "off", tool: "get_file_contents", repo: "payroll-notes", label: "private", privateRead: true }),
      rec({ mode: "off", tool: "create_branch", kind: "write", publicDestination: true, containsCanary: true }),
    ];
    const steps = buildSteps(scenario, { transcript, events: [], outcome, evidence: [] });
    expect(steps.map((s) => s.result)).toEqual(["allowed", "allowed", "allowed"]);
    expect(steps.map((s) => s.evidence.outcome?.tool)).toEqual(["list_issues", "get_file_contents", "create_branch"]);
    expect(steps[0]!.held).toEqual([]);
    expect(steps[2]!.held).toEqual(["private data", "text written by someone outside the project"]);
    expect(steps[2]!.evidence.callId).toBe("t3");
  });

  it("phraseFromScenario: placeholders come from the call's arguments", () => {
    const steps = buildSteps(scenario, attested());
    expect(steps[0]!.phrase).toBe("list the issues on acme/website");
    expect(steps[1]!.phrase).toBe("read README.md in acme/payroll-notes");
    expect(steps[2]!.phrase).toBe("create the branch about-the-author in acme/website");
  });

  it("phrase falls back to the toolcall_end arguments, and a tool without a template gets a plain phrase", () => {
    const transcript = [toolcallEnd("a", "list_issues", { owner: "o", repo: "r" }), start("b", "mystery_tool", {})];
    const outcome = [rec({ owner: "o", repo: "r" }), rec({ tool: "mystery_tool" })];
    const steps = buildSteps(scenario, { transcript, events: [], outcome, evidence: [] });
    expect(steps[0]!.phrase).toBe("list the issues on o/r");
    expect(steps[1]!.phrase).toBe("use the mystery_tool tool");
  });

  it("heldUsesPlainWords: no class identifiers in held", () => {
    const steps = buildSteps(scenario, attested());
    const plain = new Set(Object.values(PLAIN_CLASS));
    for (const s of steps) {
      for (const h of s.held) {
        expect(plain.has(h)).toBe(true);
        expect(h).not.toMatch(/third-party|local-untrusted/);
      }
    }
    expect(PLAIN_CLASS).toEqual({
      "third-party": "text written by someone outside the project",
      private: "private data",
      "local-untrusted": "content from an unverified source",
      public: "public content",
    });
  });

  it("plain reasons: the two named codes, and refused: <CODE> for the rest", () => {
    expect(PLAIN_REASON.UNSAFE_SESSION).toBe("a write in a session that couldn't prove where its requests came from");
    expect(plainReason("BAD_SIGNATURE")).toBe("refused: BAD_SIGNATURE");
    expect(plainReason("UNSAFE_SESSION")).toBe(PLAIN_REASON.UNSAFE_SESSION);
  });

  it("an expired policy reads as a configuration failure to fix, not a block", () => {
    expect(plainReason("POLICY_EXPIRED")).toBe("the signed policy had expired, so nothing could pass until it was renewed");
    expect(PLAIN_RULE.POLICY_EXPIRED).toMatch(/expired/);
    expect(PLAIN_RULE.POLICY_EXPIRED).toMatch(/not a sign of an attack/);
  });

  it("a stale call or run reads as a time limit, not an attack: the server's for an MCP call, the gate's for a local step", () => {
    expect(plainReason("EXPIRED")).toBe(
      "the call was stamped more than 5 seconds from the server's clock, or its run started more than 30 minutes before that clock or more than 5 seconds after it",
    );
    expect(plainReason("EXPIRED", true)).toBe("the run started more than 30 minutes before the step, or more than 5 seconds after it, so the step was not allowed");
    expect(PLAIN_RULE.EXPIRED).toMatch(/server's clock/);
    expect(PLAIN_RULE.EXPIRED).toMatch(/not a sign of an attack/);
  });

  it("a call still waiting for its answer is left out until the run is complete, then shown as having no recorded answer", () => {
    const logs = { transcript: [start("c1", "list_issues", { owner: "o", repo: "r" })], events: [{ type: "call", callId: "c1", tool: "list_issues" }], outcome: [], evidence: [] };
    expect(buildSteps(scenario, logs)).toEqual([]);
    const done = buildSteps(scenario, logs, { complete: true });
    expect(done).toHaveLength(1);
    expect(done[0]!.result).toBe("error");
    expect(done[0]!.reason).toBe("no answer was recorded before the run ended");
  });

  it("error results: a server error event, and a tool that returned an error", () => {
    const transcript = [start("e1", "list_issues", { owner: "o", repo: "r" }), start("e2", "list_issues", { owner: "o", repo: "r" })];
    const events = [
      { type: "call", callId: "e1", tool: "list_issues" },
      { type: "error", callId: "e1", tool: "list_issues", code: "CONNECT_FAILED" },
    ];
    const outcome = [rec({ isError: true })];
    const steps = buildSteps(scenario, { transcript, events, outcome, evidence: [] });
    expect(steps.map((s) => s.result)).toEqual(["error", "error"]);
    expect(steps[0]!.reason).toBe("the call failed before the server answered (CONNECT_FAILED)");
    expect(steps[1]!.reason).toBe("the tool returned an error");
  });

  it("builds steps from the outcome log alone when the transcript has none", () => {
    const steps = buildSteps(scenario, { transcript: [], events: [], outcome: [rec({ callId: "z1" })], evidence: [] });
    expect(steps).toHaveLength(1);
    expect(steps[0]!.phrase).toBe("list the issues on acme/website");
  });

  it("tolerates junk entries in the logs", () => {
    const steps = buildSteps(scenario, { transcript: [null, 4, "x", { type: 3 }], events: [null, "e"], outcome: [], evidence: [undefined] });
    expect(steps).toEqual([]);
  });
  it("recordedOnRun: a real run gives 19 steps, 2 refused with the plain influence reason, each with its callId", () => {
    const steps = buildSteps(scenario, recorded(), { complete: true });
    expect(steps).toHaveLength(19);
    expect(steps.map((s) => s.index)).toEqual(Array.from({ length: 19 }, (_, i) => i + 1));
    const refused = steps.filter((s) => s.result === "refused");
    expect(refused.map((s) => s.index)).toEqual([16, 18]);
    for (const s of refused) {
      expect(s.reason).toBe(PLAIN_REASON.INFLUENCE_DENIED);
      expect(s.code).toBe("INFLUENCE_DENIED");
      expect(s.rule).toBe(PLAIN_RULE.INFLUENCE_DENIED);
      expect(s.evidence.outcome?.verdict).toBe("INFLUENCE_DENIED");
    }
    for (const s of steps) {
      expect(s.evidence.callId).toMatch(/^call_/);
      expect(s.evidence.rid).toBe("SUyYBVuAsq3R8yX393JwDQ");
      expect(s.evidence.events.length).toBeGreaterThan(0);
      expect(s.evidence.evidence.length).toBeGreaterThan(0);
      expect(s.held).not.toContain("public content");
      expect(s.phrase).not.toMatch(/ {2}|…| (in|on|of|for|from|into|to)$/);
    }
    expect(steps[3]!.phrase).toBe("read the top level of acme/website");
    expect(steps[5]!.held).toEqual(["private data", "text written by someone outside the project"]);
    expect(steps.filter((s) => s.result === "error").map((s) => s.index)).toEqual([]);
    expect(steps.filter((s) => s.result !== "refused").every((s) => s.code === undefined && s.rule === undefined)).toBe(true);
  });

  it("finalAnswer: the text of the last assistant message, never its thinking", () => {
    const answer = finalAnswer(recorded().transcript);
    expect(answer).toBe("Done.");
    const msg = (content: unknown[]) => ({ type: "message_end", message: { role: "assistant", content } });
    expect(finalAnswer([msg([{ type: "text", text: "first" }]), msg([{ type: "thinking", thinking: "x" }, { type: "text", text: "done." }])])).toBe("done.");
    // a run that ended on a tool call has no final answer
    expect(finalAnswer([msg([{ type: "text", text: "let me look" }, { type: "toolCall", id: "a", name: "mcp__github__list_issues", arguments: {} }])])).toBeUndefined();
    expect(finalAnswer([{ type: "message_end", message: { role: "user", content: [{ type: "text", text: "hi" }] } }])).toBeUndefined();
    expect(finalAnswer([null, 3, { type: "message_end" }])).toBeUndefined();
  });

  it("held never lists public content", () => {
    const transcript = [start("p1", "search_repositories", { query: "acme" }), start("p2", "list_issues", { owner: "acme", repo: "website" })];
    const events = [
      { type: "response", callId: "p1", tool: "search_repositories", isError: false, classes: classes({ public: 2 }) },
      { type: "response", callId: "p2", tool: "list_issues", isError: false, classes: classes({ public: 2, "third-party": 1 }) },
    ];
    const outcome = [rec({ callId: "p1", tool: "search_repositories", label: "public" }), rec({ callId: "p2", label: "third-party" })];
    const steps = buildSteps(scenario, { transcript, events, outcome, evidence: [] });
    expect(steps[1]!.held).toEqual([]);
    const off = buildSteps(scenario, { transcript, events: [], outcome: outcome.map((o) => ({ ...o, callId: undefined, mode: "off" })), evidence: [] });
    expect(off[1]!.held).toEqual([]);
  });

  it("an empty or missing placeholder argument gives a fallback phrase, never a gap", () => {
    const transcript = [
      start("f1", "get_file_contents", { owner: "acme", repo: "website", path: "" }),
      start("f2", "get_file_contents", { owner: "acme", repo: "website" }),
      start("f3", "create_branch", { owner: "acme", repo: "website", branch: "  " }),
      start("f4", "search_repositories", {}),
      start("f5", "create_branch", { branch: "b" }),
    ];
    const outcome = ["f1", "f2", "f3", "f4", "f5"].map((id) => rec({ callId: id }));
    const steps = buildSteps(scenario, { transcript, events: [], outcome, evidence: [] });
    expect(steps.map((s) => s.phrase)).toEqual([
      "read the top level of acme/website",
      "read the top level of acme/website",
      "use the create_branch tool on acme/website",
      "use the search_repositories tool",
      "use the create_branch tool",
    ]);
  });

  it("offRunPairsByToolName: a record pairs with the first unmatched call of the same tool", () => {
    // two calls made in parallel can reach the server in the other order
    const transcript = [
      start("t1", "list_issues", { owner: "acme", repo: "website" }),
      start("t2", "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
      start("t3", "list_issues", { owner: "acme", repo: "roadmap" }),
    ];
    const outcome = [
      rec({ mode: "off", tool: "get_file_contents", repo: "payroll-notes", label: "private", privateRead: true }),
      rec({ mode: "off", repo: "website", label: "third-party" }),
      rec({ mode: "off", repo: "roadmap", isError: true }),
    ];
    const steps = buildSteps(scenario, { transcript, events: [], outcome, evidence: [] });
    expect(steps.map((s) => [s.tool, s.evidence.outcome?.tool, s.evidence.outcome?.repo])).toEqual([
      ["list_issues", "list_issues", "website"],
      ["get_file_contents", "get_file_contents", "payroll-notes"],
      ["list_issues", "list_issues", "roadmap"],
    ]);
    expect(steps.map((s) => s.result)).toEqual(["allowed", "allowed", "error"]);
  });
});

describe("local tool rows", () => {
  const local = loadScenario(join(import.meta.dirname, "../../scenarios/github-issue-replay-local"));
  const rules = {
    v: 1,
    folders: [
      { path: ".", access: ["read"] },
      { path: "website", access: ["read", "write"], label: "public", destination: "public" },
      { path: "notes", access: ["read", "write"], destination: "private" },
    ],
    programs: ["cat", "ls"],
  };
  const lstart = (id: string, tool: string, args: Record<string, unknown>) => ({ type: "tool_execution_start", toolCallId: id, toolName: tool, args });
  const lend = (id: string, tool: string, isError = false) => ({ type: "tool_execution_end", toolCallId: id, toolName: tool, isError });
  const stamp = (svc: string, rcv: string) => ({ v: 4, svc, inst: "pi-1", rid: "r1", ts: 5, sess: "", rcv, bind: "b", ext: "", prev: "p", sig: encode(utf8(svc)) });
  const PROOF = buildTree([{ salt: randomBytes(16), path: "session/pi/local:bash" }], 2, "v1").proofFor("session/pi/local:bash");
  /** The token of [origin block, hop block], the hop's holding `entries` under `influence`, as a local record's `blocks`. */
  const blocksToken = (entries: object[]) =>
    writeToken([makeBlock({}), makeBlock({ influence: entries as JsonValue[] })] as unknown as JsonValue);
  /** A local record as the extension writes it, its decision, chain, proof and blocks as tokens. */
  const localRecord = (callId: string, tool: string, extra: { verdict?: string; resolved?: object; influence?: object[]; blocks?: string }) => ({
    v: 2,
    type: "local",
    tool,
    callId,
    rid: "r1",
    now: 5,
    input: {},
    decision: writeToken({
      callId,
      resolved: (extra.resolved ?? { paths: [], programs: [], parse: "ok", readOnly: false }) as JsonValue,
      verdict: extra.verdict ?? "OK",
      routeAllowed: true,
      rulesHash: "h",
    }),
    chain: writeToken([stamp("session", "pi"), stamp("pi", `local:${tool}`)]),
    proof: writeToken(PROOF),
    blocks: extra.blocks ?? blocksToken(extra.influence ?? []),
  });
  const levent = (callId: string, tool: string, verdict: string) => ({ ts: 1, type: "local", tool, callId, rid: "r1", verdict });

  function run() {
    const transcript = [
      lstart("l1", "write", { path: "website/CHANGELOG.md", content: "x" }),
      lend("l1", "write"),
      start("c1", "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
      lstart("l2", "bash", { command: "cat notes/a.md > website/b.md" }),
      lstart("l3", "bash", { command: "cat $HOME/x" }),
      lstart("l4", "read", { path: "/etc/hosts" }),
    ];
    const events = [
      levent("l1", "write", "OK"),
      { ts: 2, type: "response", server: "github", tool: "get_file_contents", callId: "c1", rid: "r1", verify: "OK", added: ["private"], isError: false, classes: classes({ private: 1 }) },
      levent("l2", "bash", "INFLUENCE_DENIED"),
      levent("l3", "bash", "UNCHECKABLE"),
      levent("l4", "read", "PATH_NOT_ALLOWED"),
    ];
    const evidence = [
      { v: 2, type: "client", keyring: "k", root: "r", rules: writeToken(rules as JsonValue), rulesProof: null },
      localRecord("l1", "write", { resolved: { paths: [{ need: "write", at: "website/CHANGELOG.md" }], programs: [], parse: "ok", readOnly: false } }),
      localRecord("l2", "bash", {
        verdict: "INFLUENCE_DENIED",
        resolved: { paths: [{ need: "read", at: "notes/a.md" }, { need: "write", at: "website/b.md" }], programs: [{ name: "cat", via: "list" }], parse: "ok", readOnly: false },
        influence: [{ cls: "private", src: "mcp:github.get_file_contents", h: "x" }],
      }),
      localRecord("l3", "bash", { verdict: "UNCHECKABLE", resolved: { paths: [], programs: [{ name: "cat", via: "uncheckable" }], parse: "ok", readOnly: false } }),
      localRecord("l4", "read", { verdict: "PATH_NOT_ALLOWED", resolved: { paths: [{ need: "read", at: "outside" }], programs: [], parse: "ok", readOnly: false } }),
    ];
    return { transcript, events, outcome: [rec({ callId: "c1", rid: "r1", tool: "get_file_contents", repo: "payroll-notes", label: "private" })], evidence };
  }

  it("a local write, a local refusal and an MCP call are rows in order, with the scenario's phrases", () => {
    const steps = buildSteps(local, run(), { complete: true });
    expect(steps.map((s) => [s.index, s.tool, s.phrase, s.result])).toEqual([
      [1, "write", "write website/CHANGELOG.md", "allowed"],
      [2, "get_file_contents", "read README.md in acme/payroll-notes", "allowed"],
      [3, "bash", "run the command cat notes/a.md > website/b.md", "refused"],
      [4, "bash", "run the command cat $HOME/x", "refused"],
      [5, "read", "read /etc/hosts", "refused"],
    ]);
  });

  it("the plain reasons: the existing one for the influence rule, and the two fixed ones for scope and uncheckable", () => {
    const steps = buildSteps(local, run(), { complete: true });
    expect(steps[2]).toMatchObject({ code: "INFLUENCE_DENIED", reason: PLAIN_REASON.INFLUENCE_DENIED, held: ["private data"] });
    expect(steps[2]!.rule).toMatch(/public folder/);
    expect(steps[3]).toMatchObject({ code: "UNCHECKABLE", reason: "couldn't be checked" });
    expect(steps[4]).toMatchObject({ code: "PATH_NOT_ALLOWED", reason: "outside what this session may do" });
    expect(plainReason("SCOPE_DENIED")).toBe("outside what this session may do");
    expect(steps[0]!.reason).toBeUndefined();
  });

  it("an EXPIRED refusal reads the gate's age limits on a local row and the server's freshness check on an MCP row", () => {
    const logs = {
      transcript: [lstart("l9", "read", { path: "website/README.md" }), start("c9", "list_issues", { owner: "acme", repo: "website" })],
      events: [levent("l9", "read", "EXPIRED")],
      outcome: [rec({ callId: "c9", rid: "r1", verdict: "EXPIRED" })],
      evidence: [],
    };
    const [step, call] = buildSteps(local, logs, { complete: true });
    expect(step).toMatchObject({ tool: "read", result: "refused", code: "EXPIRED", reason: plainReason("EXPIRED", true) });
    expect(step!.rule).toBe(
      "A local action is refused when its run started more than 30 minutes before it, or more than 5 seconds after it. That is a limit, not a sign of an attack: a new prompt starts a new run.",
    );
    expect(call).toMatchObject({ tool: "list_issues", result: "refused", code: "EXPIRED", reason: plainReason("EXPIRED"), rule: PLAIN_RULE.EXPIRED });
    expect(call!.reason).not.toBe(step!.reason);
    expect(call!.rule).not.toBe(step!.rule);
  });

  it("the rule that fired is the folder with its access and destination, or the program, from the record and the signed rules", () => {
    const steps = buildSteps(local, run(), { complete: true });
    expect(steps[0]!.local).toMatchObject({ verdict: "OK", routeAllowed: true });
    expect(steps[0]!.local!.checks).toEqual([{ what: "write to website/CHANGELOG.md", rule: "the folder website allows read and write; writes there count as public; what is read there is public" }]);
    expect(steps[2]!.local!.checks).toEqual([
      { what: "read notes/a.md", rule: "the folder notes allows read and write; writes there count as private" },
      { what: "write to website/b.md", rule: "the folder website allows read and write; writes there count as public; what is read there is public" },
      { what: "run cat", rule: "a program on the session's list" },
    ]);
    expect(steps[3]!.local!.checks).toEqual([{ what: "run cat", rule: "a program that couldn't be checked" }]);
    expect(steps[4]!.local!.checks).toEqual([{ what: "read outside", rule: "outside every folder this session may use" }]);
  });

  it("a row's evidence holds its own events and evidence lines; the client record is not part of it", () => {
    const steps = buildSteps(local, run(), { complete: true });
    expect(steps[2]!.evidence.callId).toBe("l2");
    expect(steps[2]!.evidence.rid).toBe("r1");
    expect(steps[2]!.evidence.events).toEqual([levent("l2", "bash", "INFLUENCE_DENIED")]);
    expect(steps[2]!.evidence.evidence.map((e) => (e as any).type)).toEqual(["local"]);
  });

  it("aLocalRecordsDisplayHoldsItsBlocksAndTheEntriesOfItsHop", () => {
    const logs = run();
    const steps = buildSteps(local, logs, { complete: true });
    // the record as the evidence file holds it, and its tokens decoded beside it
    expect(steps[2]!.evidence.evidence).toEqual([logs.evidence[2]]);
    const [display] = steps[2]!.evidence.displays;
    expect(display).toEqual({
      chain: [stamp("session", "pi"), stamp("pi", "local:bash")],
      blocks: readBlocks((logs.evidence[2] as { blocks: string }).blocks),
      influence: [{ cls: "private", src: "mcp:github.get_file_contents", h: "x" }],
      proof: PROOF,
    });
    expect(display!.blocks).toHaveLength(2);
    // a hop that names no influence holds no entries
    expect(steps[0]!.evidence.displays[0]).toMatchObject({ influence: [] });
  });

  it("aBlocksTokenThatDoesNotReadIsNamedUnreadable", () => {
    const logs = run();
    const l1 = logs.evidence[1] as Record<string, unknown>;
    logs.evidence[1] = { ...l1, chain: "not a token", blocks: "not a token" } as never;
    expect(buildSteps(local, logs, { complete: true })[0]!.evidence.displays).toEqual([{ proof: PROOF, unreadable: ["chain", "blocks"] }]);
    // blocks that read, holding an item that is not an entry: the blocks are shown and the entries are not
    logs.evidence[1] = { ...l1, blocks: blocksToken([{ cls: "private" }]) } as never;
    const [display] = buildSteps(local, logs, { complete: true })[0]!.evidence.displays;
    expect(display).toMatchObject({ unreadable: ["influence"] });
    expect(display!.blocks).toHaveLength(2);
    expect(display!.influence).toBeUndefined();
  });

  it("aLocalRecordWithNoBlocksNamesItsInfluenceUnreadable", () => {
    const logs = run();
    const l1 = logs.evidence[1] as Record<string, unknown>;
    logs.evidence[1] = { ...l1, blocks: writeToken([]) } as never;
    const [display] = buildSteps(local, logs, { complete: true })[0]!.evidence.displays;
    expect(display).toEqual({ chain: expect.any(Array), blocks: [], proof: PROOF, unreadable: ["influence"] });
  });

  it("a local tool that errored is an error row; a call with no answer is left out until the run is complete", () => {
    const logs = run();
    logs.transcript.push(lend("l1", "write", true));
    expect(buildSteps(local, logs, { complete: true })[0]).toMatchObject({ result: "error", reason: "the tool returned an error" });
    const waiting = { transcript: [lstart("l9", "bash", { command: "ls" })], events: [], outcome: [], evidence: [] };
    expect(buildSteps(local, waiting, { complete: false })).toEqual([]);
    expect(buildSteps(local, waiting, { complete: true })[0]).toMatchObject({ tool: "bash", result: "error", reason: "no answer was recorded before the run ended" });
  });

  it("a scenario without local tools does not turn built-in tool names into rows", () => {
    const steps = buildSteps(scenario, { ...run(), transcript: [lstart("l1", "bash", { command: "ls" })], events: [], evidence: [] }, { complete: true });
    expect(steps.map((s) => s.tool)).toEqual(["get_file_contents"]);
  });

  it("a local argument is capped at 80 characters in the phrase", () => {
    const long = "x".repeat(200);
    const steps = buildSteps(local, { transcript: [lstart("l1", "bash", { command: long }), lend("l1", "bash")], events: [], outcome: [], evidence: [] }, { complete: true });
    expect(steps[0]!.phrase).toBe(`run the command ${"x".repeat(80)}…`);
  });
});

describe("the tokens of a row's MCP records", () => {
  /** The recorded run's row for `callId`, with its records and their displays. */
  const rowOf = (logs: ReturnType<typeof recorded>, callId: string) => buildSteps(scenario, logs, { complete: true }).find((s) => s.evidence.callId === callId)!;
  const recordsOf = (logs: ReturnType<typeof recorded>, callId: string) => logs.evidence.filter((r) => r.callId === callId);

  it("a call's chain and blocks and a response's attestation are decoded beside the records, which are as the file holds them", () => {
    const logs = recorded();
    const [call, response] = recordsOf(logs, "call_0716zl9y");
    const row = rowOf(logs, "call_0716zl9y");
    expect(row.evidence.evidence).toEqual([call, response]);
    expect(row.evidence.evidence.every((r) => !Object.hasOwn(r as object, "display"))).toBe(true);
    const attestation = readAttestation(response.result._meta["paztport/attestation"]);
    expect(row.evidence.displays).toEqual([
      { chain: readChain(call.params._meta["paztport/chain"]), blocks: readBlocks(call.params._meta["paztport/extensions"]) },
      { attestation, labels: expect.any(Array) },
    ]);
  });

  it("aResponsesDisplayHoldsTheLabelsItsAttestationSigned", () => {
    const logs = recorded();
    const response = recordsOf(logs, "call_288ffhop")[1]!;
    const [, shown] = rowOf(logs, "call_288ffhop").evidence.displays;
    expect(shown!.labels).toEqual([{ cls: "third-party", cid: expect.any(String) }]);
    // every label is an item under influence in the attestation's own blocks
    const items = readAttestation(response.result._meta["paztport/attestation"]).blocks.flatMap((b) => [...(b.items.influence ?? [])]);
    expect(items).toHaveLength(1);
    // an item that does not read as a label is not shown, and the others still are
    const wire = readToken(response.result._meta["paztport/attestation"]) as { blocks: { items: { influence?: JsonValue[] } }[] };
    wire.blocks.forEach((b) => b.items.influence?.push({ cls: "private" }, "x"));
    response.result._meta["paztport/attestation"] = writeToken(wire as unknown as JsonValue);
    const [, edited] = rowOf(logs, "call_288ffhop").evidence.displays;
    expect(edited!.labels).toEqual(shown!.labels);
    expect(edited!.unreadable).toBeUndefined();
  });

  it("a refusal carries no attestation, so its response has nothing to decode", () => {
    const logs = recorded();
    const row = rowOf(logs, "call_46fyq3ur");
    expect(row.result).toBe("refused");
    expect(row.evidence.displays).toEqual([{ chain: expect.any(Array), blocks: expect.any(Array) }, {}]);
  });

  it("a token that does not read is named, and the record is still shown as the file holds it", () => {
    const logs = recorded();
    const [call, response] = recordsOf(logs, "call_0716zl9y");
    call.params._meta["paztport/chain"] = "not a token";
    call.params._meta["paztport/extensions"] = "not a token";
    response.result._meta["paztport/attestation"] = { chain: [] };
    const row = rowOf(logs, "call_0716zl9y");
    expect(row.evidence.evidence).toEqual([call, response]);
    expect(row.evidence.displays).toEqual([{ unreadable: ["paztport/chain", "paztport/extensions"] }, { unreadable: ["paztport/attestation"] }]);
  });
});

describe("the two outcomes the client reports itself", () => {
  const call = { type: "tool_execution_start", toolCallId: "w1", toolName: "mcp__github__get_file_contents", args: { owner: "acme", repo: "payroll-notes", path: "README.md" } };

  it("aWithheldResultIsAnErrorStepThatSaysSo", () => {
    const events = [
      { ts: 1, type: "call", server: "github", tool: "get_file_contents", callId: "w1", rid: "r1", session: "attested" },
      { ts: 2, type: "response", server: "github", tool: "get_file_contents", callId: "w1", rid: "r1", verify: "EXTENSION_REQUIRED", added: ["private"], withheld: true, isError: true, classes: classes({ private: 1 }) },
    ];
    // the tool ran, so the server's own record says ALLOWED; the step is about what the client did with the result
    const outcome = [rec({ callId: "w1", rid: "r1", tool: "get_file_contents", repo: "payroll-notes", label: "private" })];
    const [step] = buildSteps(scenario, { transcript: [call], events, outcome, evidence: [] }, { complete: true });
    expect(step).toMatchObject({
      result: "error",
      reason: "the client withheld the result: the response required an extension the client does not act on",
      held: [],
    });
    expect(step!.code).toBeUndefined();
  });

  it("aStepCarriesWhatTheClientRecorded", () => {
    // the response event's `added`, whatever the reply's verification: the page's labels panel shows it
    const added = (response: Record<string, unknown>) => {
      const events = [{ ts: 2, type: "response", server: "github", tool: "get_file_contents", callId: "w1", rid: "r1", isError: false, ...response }];
      return buildSteps(scenario, { transcript: [call], events, outcome: [], evidence: [] }, { complete: true })[0]!.added;
    };
    expect(added({ verify: "OK", added: ["private"] })).toEqual(["private"]);
    expect(added({ verify: "BAD_SIGNATURE", added: ["local-untrusted"] })).toEqual(["local-untrusted"]);
    expect(added({ verify: "OK", added: [] })).toEqual([]);
    // a refusal adds nothing and records no `added`; a list that is not of classes is not shown
    expect(added({ verdict: "INFLUENCE_DENIED", isError: true })).toBeUndefined();
    expect(added({ verify: "OK", added: ["Private"] })).toBeUndefined();
    expect(added({ verify: "OK", added: "private" })).toBeUndefined();
  });

  it("aCallInANoCallsSessionIsAnErrorStepThatSaysSo", () => {
    const events = [
      { ts: 1, type: "error", server: "github", tool: "get_file_contents", callId: "w1", code: "NO_CALLS", reason: "EXTENSION_REQUIRED" },
    ];
    const [step] = buildSteps(scenario, { transcript: [call], events, outcome: [], evidence: [] }, { complete: true });
    expect(step).toMatchObject({ result: "error", reason: "the call was not sent: no session with the server gave what the client requires of it (EXTENSION_REQUIRED)" });
    expect(step!.code).toBeUndefined();
  });
});
