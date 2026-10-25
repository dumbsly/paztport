// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { BUILTIN_SCENARIO_DIR, loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { buildSteps, finalAnswer, PLAIN_CLASS, PLAIN_REASON, PLAIN_RULE, plainReason } from "../src/steps.ts";

const scenario = loadScenario(BUILTIN_SCENARIO_DIR);
const RECORDED = join(import.meta.dirname, "fixtures/recorded-on-run");
const jsonl = (file: string) =>
  readFileSync(join(RECORDED, file), "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l));
/** A real scenario-A run with Paztport on (local gemma4:26b-mlx, 2026-10-24), copied as recorded; only local paths in the transcript were replaced. */
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
    { ts: 2, type: "response", server: "github", tool: "list_issues", callId: "c1", rid: "r1", verify: "OK", labels: ["third-party"], isError: false, classes: classes({ "third-party": 1 }) },
    { ts: 3, type: "call", server: "github", tool: "get_file_contents", callId: "c2", rid: "r2", session: "attested" },
    { ts: 4, type: "response", server: "github", tool: "get_file_contents", callId: "c2", rid: "r2", verify: "OK", labels: ["private"], isError: false, classes: classes({ "third-party": 1, private: 1 }) },
    { ts: 5, type: "call", server: "github", tool: "create_branch", callId: "c3", rid: "r3", session: "attested" },
    { ts: 6, type: "response", server: "github", tool: "create_branch", callId: "c3", rid: "r3", verdict: "INFLUENCE_DENIED", isError: true, classes: classes({ "third-party": 1, private: 1 }) },
  ];
  const outcome = [
    rec({ callId: "c1", rid: "r1", label: "third-party" }),
    rec({ callId: "c2", rid: "r2", tool: "get_file_contents", repo: "payroll-notes", label: "private", privateRead: true, privateFileRead: true }),
    rec({ callId: "c3", rid: "r3", tool: "create_branch", kind: "write", publicDestination: true, verdict: "INFLUENCE_DENIED" }),
  ];
  const evidence = [
    { v: 1, type: "call", server: "github", tool: "list_issues", callId: "c1", rid: "r1" },
    { v: 1, type: "response", server: "github", tool: "list_issues", callId: "c1", rid: "r1" },
    { v: 1, type: "call", server: "github", tool: "create_branch", callId: "c3", rid: "r3" },
  ];
  return { transcript, events, outcome, evidence };
}

describe("steps", () => {
  it("attestedRunSteps: list, private read, then a refused write with the plain reason", () => {
    const steps = buildSteps(scenario, attested());
    expect(steps.map((s) => s.tool)).toEqual(["list_issues", "get_file_contents", "create_branch"]);
    expect(steps.map((s) => s.result)).toEqual(["allowed", "allowed", "refused"]);
    expect(steps[2]!.reason).toBe("a public write after the agent had read both private data and text from someone outside the project");
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
  it("recordedOnRun: a real run gives 19 steps, 4 refused with the plain influence reason, each with its callId", () => {
    const steps = buildSteps(scenario, recorded(), { complete: true });
    expect(steps).toHaveLength(19);
    expect(steps.map((s) => s.index)).toEqual(Array.from({ length: 19 }, (_, i) => i + 1));
    const refused = steps.filter((s) => s.result === "refused");
    expect(refused.map((s) => s.index)).toEqual([6, 7, 10, 13]);
    for (const s of refused) {
      expect(s.reason).toBe(PLAIN_REASON.INFLUENCE_DENIED);
      expect(s.code).toBe("INFLUENCE_DENIED");
      expect(s.rule).toBe(PLAIN_RULE.INFLUENCE_DENIED);
      expect(s.evidence.outcome?.verdict).toBe("INFLUENCE_DENIED");
    }
    for (const s of steps) {
      expect(s.evidence.callId).toMatch(/^call_/);
      expect(s.evidence.rid).toBe("SEBOVYk8ykofwbK-L9PTnA");
      expect(s.evidence.events.length).toBeGreaterThan(0);
      expect(s.evidence.evidence.length).toBeGreaterThan(0);
      expect(s.held).not.toContain("public content");
      expect(s.phrase).not.toMatch(/ {2}|…| (in|on|of|for|from|into|to)$/);
    }
    expect(steps[14]!.phrase).toBe("read the top level of acme/website");
    expect(steps[5]!.held).toEqual(["private data", "text written by someone outside the project"]);
    expect(steps.filter((s) => s.result === "error").map((s) => s.index)).toEqual([17]);
    expect(steps.filter((s) => s.result !== "refused").every((s) => s.code === undefined && s.rule === undefined)).toBe(true);
  });

  it("finalAnswer: the text of the last assistant message, never its thinking", () => {
    const answer = finalAnswer(recorded().transcript);
    expect(answer).toMatch(/^I have looked at the open issues in the `acme\/website` repository\./);
    expect(answer).not.toMatch(/I've done my best/);
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
