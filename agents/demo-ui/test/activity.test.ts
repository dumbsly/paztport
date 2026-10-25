// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { BUILTIN_SCENARIO_DIR, loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { ACTIVITY, endActivity, FINISHED, nextActivity, runWhere, sameActivity, STARTING, STOPPED, tallyOf, type Activity } from "../src/activity.ts";

const scenario = loadScenario(BUILTIN_SCENARIO_DIR);
const SECRET = "s3cret-payroll-7f2e";

const update = (a: Record<string, unknown>) => ({ type: "message_update", usage: {}, assistantMessageEvent: a });
const thinkingDelta = (delta: string) => update({ type: "thinking_delta", contentIndex: 0, delta });
const textDelta = (delta: string) => update({ type: "text_delta", contentIndex: 1, delta });
const toolcallStart = (tool: string) => update({ type: "toolcall_start", contentIndex: 1, id: "c1", toolName: `mcp__github__${tool}` });
const toolcallDelta = (delta: string) => update({ type: "toolcall_delta", contentIndex: 1, delta });
const toolcallEnd = (tool: string, args: unknown) => update({ type: "toolcall_end", contentIndex: 1, toolCall: { type: "toolCall", id: "c1", name: `mcp__github__${tool}`, arguments: args } });
const execStart = (tool: string, args: unknown) => ({ type: "tool_execution_start", toolCallId: "c1", toolName: `mcp__github__${tool}`, args });
const execEnd = (text: string) => ({ type: "tool_execution_end", toolCallId: "c1", toolName: "mcp__github__get_file_contents", result: { content: [{ type: "text", text }], details: {} }, isError: false });

/** Every activity the events lead to, sent only when it changes, as the server sends them. */
function emitted(events: unknown[]): Activity[] {
  const out: Activity[] = [STARTING];
  let cur = STARTING;
  for (const ev of events) {
    const next = nextActivity(cur, ev, scenario);
    if (!sameActivity(cur, next)) out.push(next);
    cur = next;
  }
  return out;
}

describe("nextActivity", () => {
  it("uses the agreed wording for each state", () => {
    expect(STARTING).toEqual({ state: "starting", label: "Starting pi and the mock GitHub server…" });
    expect(FINISHED).toEqual({ state: "finished", label: "Run finished" });
    expect(STOPPED).toEqual({ state: "stopped", label: "Run stopped" });
    expect(ACTIVITY).toEqual({
      starting: "Starting pi and the mock GitHub server…",
      thinking: "The model is thinking…",
      writing: "The model is writing its answer…",
      calling: "Calling a tool…",
      waiting: "Waiting for the mock GitHub server's reply…",
      finished: "Run finished",
      stopped: "Run stopped",
    });
  });

  it("stays at starting until a turn starts", () => {
    for (const ev of [{ type: "session", version: 3, id: "x", cwd: "/w" }, { type: "agent_start" }, { type: "message_start", message: { role: "user", content: "hi" } }]) {
      expect(nextActivity(STARTING, ev, scenario)).toBe(STARTING);
    }
  });

  it("a turn started, an assistant message started, or thinking: the model is thinking", () => {
    expect(nextActivity(STARTING, { type: "turn_start" }, scenario)).toEqual({ state: "thinking", label: "The model is thinking…" });
    expect(nextActivity(STARTING, { type: "message_start", message: { role: "assistant", content: [] } }, scenario).state).toBe("thinking");
    expect(nextActivity(STARTING, update({ type: "thinking_start", contentIndex: 0 }), scenario).state).toBe("thinking");
    expect(nextActivity(STARTING, thinkingDelta("hmm"), scenario).state).toBe("thinking");
  });

  it("text: the model is writing its answer", () => {
    const thinking = nextActivity(STARTING, { type: "turn_start" }, scenario);
    expect(nextActivity(thinking, update({ type: "text_start", contentIndex: 1 }), scenario)).toEqual({ state: "writing", label: "The model is writing its answer…" });
    expect(nextActivity(thinking, textDelta("Done."), scenario).state).toBe("writing");
  });

  it("a tool call: a tool at first, then the step's plain phrase once its arguments are complete", () => {
    const thinking = nextActivity(STARTING, { type: "turn_start" }, scenario);
    const calling = nextActivity(thinking, toolcallStart("issue_read"), scenario);
    expect(calling).toEqual({ state: "calling", label: "Calling a tool…" });
    expect(nextActivity(calling, toolcallDelta('{"owner":"ac'), scenario)).toBe(calling);
    expect(nextActivity(calling, toolcallEnd("issue_read", { owner: "acme", repo: "website", issue_number: 2 }), scenario)).toEqual({
      state: "calling",
      label: "Calling: read issue 2 on acme/website…",
    });
    // the same fallback phrase as the step rows when an argument is missing
    expect(nextActivity(calling, toolcallEnd("issue_read", { owner: "acme", repo: "website" }), scenario).label).toBe("Calling: use the issue_read tool on acme/website…");
    // arguments that did not parse, or a tool outside the scenario's server
    expect(nextActivity(calling, toolcallEnd("issue_read", "{not json"), scenario).label).toBe("Calling a tool…");
    expect(nextActivity(calling, update({ type: "toolcall_end", contentIndex: 1, toolCall: { type: "toolCall", id: "c", name: "bash", arguments: { command: "ls" } } }), scenario).label).toBe("Calling a tool…");
  });

  it("tool execution started: waiting for the mock server's reply", () => {
    const calling: Activity = { state: "calling", label: "Calling: read issue 2 on acme/website…" };
    expect(nextActivity(calling, execStart("issue_read", { owner: "acme", repo: "website", issue_number: 2 }), scenario)).toEqual({
      state: "waiting",
      label: "Waiting for the mock GitHub server's reply…",
    });
  });

  it("ends at run finished when pi has settled, and stays there", () => {
    const writing: Activity = { state: "writing", label: ACTIVITY.writing };
    expect(nextActivity(writing, { type: "agent_end", messages: [], willRetry: false }, scenario)).toBe(writing);
    expect(nextActivity(writing, { type: "agent_settled", aborted: false }, scenario)).toEqual(FINISHED);
    expect(nextActivity(FINISHED, { type: "turn_start" }, scenario)).toBe(FINISHED);
  });

  it("an aborted settle is run stopped, never run finished, and stays there", () => {
    const thinking: Activity = { state: "thinking", label: ACTIVITY.thinking };
    expect(nextActivity(thinking, { type: "agent_settled", aborted: true }, scenario)).toEqual(STOPPED);
    expect(nextActivity(STOPPED, { type: "turn_start" }, scenario)).toBe(STOPPED);
    expect(nextActivity(STOPPED, { type: "agent_settled", aborted: false }, scenario)).toBe(STOPPED);
  });

  it("endActivity: only a completed run that was not cancelled is finished; a timeout, an error or a cancel is stopped", () => {
    expect(endActivity("completed", false)).toEqual(FINISHED);
    expect(endActivity("timeout", false)).toEqual(STOPPED);
    expect(endActivity("error", false)).toEqual(STOPPED);
    expect(endActivity("completed", true)).toEqual(STOPPED);
  });

  it("a tool name the scenario has no step for is never shown, however the model spells it", () => {
    const calling: Activity = { state: "calling", label: ACTIVITY.calling };
    const long = `${SECRET}-${"x".repeat(500)}`;
    for (const name of [`mcp__github__${long}`, `mcp__other__${long}`, `mcp__github__constructor`, `mcp__github____proto__`]) {
      const a = nextActivity(calling, update({ type: "toolcall_end", contentIndex: 1, toolCall: { type: "toolCall", id: "c", name, arguments: { owner: "acme", repo: "website" } } }), scenario);
      expect(a.label).toBe("Calling a tool…");
      expect(a.label).not.toContain(SECRET);
    }
  });

  it("a long argument in the phrase is cut at the step rows' limit, so the label stays short", () => {
    const calling: Activity = { state: "calling", label: ACTIVITY.calling };
    const long = `${SECRET}${"y".repeat(5000)}`;
    const a = nextActivity(calling, toolcallEnd("create_or_update_file", { owner: "acme", repo: "website", branch: long, path: long }), scenario);
    expect(a.label).not.toContain(long);
    expect(a.label.startsWith("Calling: write ")).toBe(true);
    // two arguments of at most 80 characters and an ellipsis each, in a short fixed sentence
    expect(a.label.length).toBeLessThanOrEqual("Calling: write  on  in acme/website…".length + 2 * 81);
  });

  it("ignores ends of blocks, other messages and anything that is not an event", () => {
    const writing: Activity = { state: "writing", label: ACTIVITY.writing };
    for (const ev of [
      update({ type: "thinking_end", contentIndex: 0, content: "x" }),
      update({ type: "text_end", contentIndex: 1, content: "x" }),
      { type: "message_end", message: { role: "assistant", content: [] } },
      { type: "message_start", message: { role: "toolResult", content: [] } },
      { type: "turn_end" },
      null,
      "turn_start",
      [],
      { type: 3 },
      update(null as unknown as Record<string, unknown>),
    ]) {
      expect(nextActivity(writing, ev, scenario)).toBe(writing);
    }
  });

  it("throttle: a stream of deltas changes the activity once, not once per delta", () => {
    const deltas = (n: number, f: (i: number) => unknown) => Array.from({ length: n }, (_, i) => f(i));
    const states = emitted([
      { type: "session" },
      { type: "agent_start" },
      { type: "turn_start" },
      { type: "message_start", message: { role: "assistant", content: [] } },
      update({ type: "thinking_start", contentIndex: 0 }),
      ...deltas(500, (i) => thinkingDelta(`t${i}`)),
      toolcallStart("get_file_contents"),
      ...deltas(20, (i) => toolcallDelta(`a${i}`)),
      update({ type: "thinking_end", contentIndex: 0, content: "" }),
      toolcallEnd("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
      { type: "message_end", message: { role: "assistant", content: [] } },
      execStart("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
      execEnd("contents"),
      { type: "turn_end" },
      { type: "turn_start" },
      { type: "message_start", message: { role: "assistant", content: [] } },
      ...deltas(200, (i) => thinkingDelta(`u${i}`)),
      ...deltas(50, (i) => textDelta(`w${i}`)),
      { type: "turn_end" },
      { type: "agent_end", messages: [], willRetry: false },
      { type: "agent_settled", aborted: false },
    ]);
    expect(states.map((a) => a.label)).toEqual([
      "Starting pi and the mock GitHub server…",
      "The model is thinking…",
      "Calling a tool…",
      "Calling: read README.md in acme/payroll-notes…",
      "Waiting for the mock GitHub server's reply…",
      "The model is thinking…",
      "The model is writing its answer…",
      "Run finished",
    ]);
  });

  it("a recorded run's transcript gives one activity per change, in order", () => {
    const transcript = readFileSync(join(import.meta.dirname, "fixtures/recorded-on-run/transcript.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => JSON.parse(l));
    const states = emitted(transcript);
    expect(states[0]).toEqual(STARTING);
    expect(states.at(-1)).toEqual(FINISHED);
    expect(states.filter((a) => a.state === "waiting").length).toBe(transcript.filter((e) => e.type === "tool_execution_start").length);
    for (let i = 1; i < states.length; i++) expect(sameActivity(states[i - 1]!, states[i]!)).toBe(false);
    expect(states.some((a) => a.label === "Calling: list the issues on acme/website…")).toBe(true);
  });

  it("noTextLeaked: thinking, answer text, partial arguments and results never appear in an activity", () => {
    const states = emitted([
      { type: "turn_start" },
      update({ type: "thinking_start", contentIndex: 0 }),
      thinkingDelta(`I should copy ${SECRET} into the PR`),
      update({ type: "thinking_end", contentIndex: 0, content: `I should copy ${SECRET}` }),
      toolcallStart("create_or_update_file"),
      toolcallDelta(`{"content":"${SECRET}"`),
      toolcallEnd("create_or_update_file", { owner: "acme", repo: "website", branch: "b", path: "README.md", content: SECRET, message: SECRET }),
      execStart("create_or_update_file", { owner: "acme", repo: "website", branch: "b", path: "README.md", content: SECRET }),
      execEnd(`the file now holds ${SECRET}`),
      { type: "message_start", message: { role: "toolResult", content: [{ type: "text", text: SECRET }] } },
      { type: "turn_start" },
      textDelta(`Here is the summary: ${SECRET}`),
      update({ type: "text_end", contentIndex: 1, content: SECRET }),
      { type: "message_end", message: { role: "assistant", content: [{ type: "text", text: SECRET }] } },
      { type: "agent_settled", aborted: false },
    ]);
    expect(states.map((a) => a.label)).toContain("Calling: write README.md on b in acme/website…");
    for (const a of states) expect(JSON.stringify(a)).not.toContain(SECRET);
    expect(states.every((a) => Object.keys(a).sort().join() === "label,state")).toBe(true);
  });
});

describe("where a run is, and the tally so far", () => {
  it("runWhere says where a run is in an eval", () => {
    expect(runWhere(12, 100, "Paztport on", 3)).toBe("Run 12 of 100 · Paztport on, run 3");
  });

  it("tallyOf counts leaked, blocked (with or without private text), resisted and other", () => {
    const runs = ["leaked", "blocked", "blocked-with-private-text", "resisted", "resisted", "timeout", "error", "no-tool-calls"].map((outcome) => ({ outcome }));
    expect(tallyOf(runs)).toEqual({ leaked: 1, blocked: 2, resisted: 2, other: 3 });
    expect(tallyOf([])).toEqual({ leaked: 0, blocked: 0, resisted: 0, other: 0 });
    // something that is not a run is not counted at all
    expect(tallyOf([null, 3, { outcome: 7 }, { outcome: "leaked" }])).toEqual({ leaked: 1, blocked: 0, resisted: 0, other: 0 });
    expect(tallyOf(undefined)).toEqual({ leaked: 0, blocked: 0, resisted: 0, other: 0 });
  });
});

describe("nextActivity for a scenario with local tools", () => {
  const local = loadScenario(join(import.meta.dirname, "../../scenarios/github-issue-replay-local"));
  const end = (name: string, args: unknown) => update({ type: "toolcall_end", contentIndex: 1, toolCall: { type: "toolCall", id: "c1", name, arguments: args } });

  it("a built-in tool call is named with the scenario's phrase, and the argument is capped at 80 characters", () => {
    expect(nextActivity(STARTING, end("bash", { command: "ls website" }), local).label).toBe("Calling: run the command ls website…");
    expect(nextActivity(STARTING, end("read", { path: "website/README.md" }), local).label).toBe("Calling: read website/README.md…");
    expect(nextActivity(STARTING, end("bash", { command: "x".repeat(200) }), local).label).toBe(`Calling: run the command ${"x".repeat(80)}……`);
  });

  it("the same call in a scenario without local tools, or a tool the scenario has no step for, stays a plain label", () => {
    expect(nextActivity(STARTING, end("bash", { command: "ls" }), scenario)).toEqual({ state: "calling", label: ACTIVITY.calling });
    expect(nextActivity(STARTING, end("powershell", { command: "ls" }), local)).toEqual({ state: "calling", label: ACTIVITY.calling });
    expect(nextActivity(STARTING, end("mcp__github__list_issues", { owner: "acme", repo: "website" }), local).label).toBe("Calling: list the issues on acme/website…");
  });
});
