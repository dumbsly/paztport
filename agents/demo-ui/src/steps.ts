// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import type { Scenario } from "../../mock-github-mcp/src/scenario.ts";
import type { InfluenceClass } from "../../path-attest-ts/src/influence.ts";

/** One tool call, in plain words. `index` counts from 1 in the order the model made the calls. */
export type Step = {
  index: number;
  tool: string;
  phrase: string;
  /** What the agent had read before this call, in plain words. */
  held: string[];
  result: "allowed" | "refused" | "error";
  reason?: string;
  evidence: { callId?: string; rid?: string; outcome?: OutcomeRecord; events: unknown[]; evidence: unknown[] };
};
export type StepLogs = { transcript: unknown[]; events: unknown[]; outcome: OutcomeRecord[]; evidence: unknown[] };
export type BuildOptions = {
  /** The run is over: a call that never got an answer is shown (as an error) instead of being left out. */
  complete?: boolean;
};

export const PLAIN_CLASS: Record<InfluenceClass, string> = {
  "third-party": "text written by someone outside the project",
  private: "private data",
  "local-untrusted": "content from an unverified source",
  public: "public content",
};

export const PLAIN_REASON: Record<string, string> = {
  INFLUENCE_DENIED: "a public write after the agent had read both private data and text from someone outside the project",
  UNSAFE_SESSION: "a write in a session that couldn't prove where its requests came from",
};

/** The plain reason for a refusal code; a code without its own wording reads `refused: <CODE>`. */
export function plainReason(code: string): string {
  return PLAIN_REASON[code] ?? `refused: ${code}`;
}

/** Read order for `held`, so the same classes always come out in the same order. */
const CLASS_ORDER: readonly InfluenceClass[] = ["private", "third-party", "local-untrusted", "public"];
const MAX_ARG_CHARS = 80;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);

type Call = { id: string; real: boolean; name: string; args?: Obj; ended?: { isError: boolean } };

/** pi names a tool mcp__<server>__<tool>, with every character outside [A-Za-z0-9_] replaced by "_". */
function toolOf(full: string, serverId: string): string | undefined {
  const prefix = `mcp__${serverId}__`.replace(/[^A-Za-z0-9_]/g, "_");
  if (full.startsWith(prefix)) return full.slice(prefix.length);
  const m = /^mcp__[A-Za-z0-9]+__(.+)$/.exec(full);
  return m ? m[1] : undefined;
}

/** The MCP tool calls in a pi `--mode json` transcript, in the order they first appear. */
function callsOf(transcript: unknown[], serverId: string): Call[] {
  const byId = new Map<string, Call>();
  const upsert = (id: string | undefined, line: number, fullName: unknown): Call | undefined => {
    const name = typeof fullName === "string" ? toolOf(fullName, serverId) : undefined;
    const key = id ?? `line-${line}`;
    const existing = byId.get(key);
    if (existing) return existing;
    if (name === undefined) return undefined;
    const call: Call = { id: key, real: id !== undefined, name };
    byId.set(key, call);
    return call;
  };
  transcript.forEach((ev, line) => {
    if (!isObj(ev)) return;
    if (ev.type === "tool_execution_start") {
      const c = upsert(str(ev.toolCallId), line, ev.toolName);
      if (c && isObj(ev.args)) c.args = ev.args;
    } else if (ev.type === "tool_execution_end") {
      const c = upsert(str(ev.toolCallId), line, ev.toolName);
      if (c) c.ended = { isError: ev.isError === true };
    } else if (ev.type === "message_update" && isObj(ev.assistantMessageEvent)) {
      const a = ev.assistantMessageEvent;
      if (a.type === "toolcall_start") {
        upsert(str(a.id), line, a.toolName);
      } else if (a.type === "toolcall_end" && isObj(a.toolCall)) {
        const c = upsert(str(a.toolCall.id), line, a.toolCall.name);
        if (c && c.args === undefined && isObj(a.toolCall.arguments)) c.args = a.toolCall.arguments;
      }
    }
  });
  return [...byId.values()];
}

function fill(template: string, args: Obj): string {
  return template.replace(/\{([^{}]*)\}/g, (_m, key: string) => {
    const v = args[key];
    if (v === undefined || v === null) return "…";
    const s = typeof v === "string" ? v : JSON.stringify(v);
    return s.length > MAX_ARG_CHARS ? `${s.slice(0, MAX_ARG_CHARS)}…` : s;
  });
}

function groupBy(items: unknown[]): Map<string, unknown[]> {
  const out = new Map<string, unknown[]>();
  for (const it of items) {
    if (!isObj(it)) continue;
    const id = str(it.callId);
    if (id === undefined) continue;
    const list = out.get(id) ?? [];
    list.push(it);
    out.set(id, list);
  }
  return out;
}

const countsOf = (v: unknown): InfluenceClass[] | undefined => {
  if (!isObj(v)) return undefined;
  return CLASS_ORDER.filter((c) => typeof v[c] === "number" && (v[c] as number) > 0);
};

/**
 * Turns a run's logs into plain-language rows. The calls come from the transcript. Each is matched to its
 * outcome record by callId, or, for records without one (Paztport off), by order among the calls still
 * unmatched. Outcome records with no call in the transcript become rows of their own.
 */
export function buildSteps(s: Scenario, logs: StepLogs, opts: BuildOptions = {}): Step[] {
  const calls = callsOf(logs.transcript, s.serverId);
  const events = groupBy(logs.events);
  const evidence = groupBy(logs.evidence);
  const outcomes = logs.outcome.filter(isObj) as OutcomeRecord[];

  const outcomeFor = new Map<string, OutcomeRecord>();
  const taken = new Set<OutcomeRecord>();
  const byCallId = new Map<string, OutcomeRecord>();
  for (const o of outcomes) if (typeof o.callId === "string" && !byCallId.has(o.callId)) byCallId.set(o.callId, o);
  for (const c of calls) {
    const o = byCallId.get(c.id);
    if (o) {
      outcomeFor.set(c.id, o);
      taken.add(o);
    }
  }
  const spare = outcomes.filter((o) => !taken.has(o) && !(typeof o.callId === "string" && calls.some((c) => c.id === o.callId)));
  const hasErrorEvent = (id: string) => (events.get(id) ?? []).some((e) => (e as Obj).type === "error");
  const waiting = calls.filter((c) => !outcomeFor.has(c.id) && !hasErrorEvent(c.id));
  // a record that names a call the transcript lacks is not part of the by-order pairing
  const orderPool = spare.filter((o) => typeof o.callId !== "string");
  for (const c of waiting) {
    const o = orderPool.shift();
    if (!o) break;
    outcomeFor.set(c.id, o);
    taken.add(o);
  }
  // records nothing in the transcript accounts for
  const extra = outcomes.filter((o) => !taken.has(o));

  type Row = { id: string; real: boolean; tool: string; args: Obj; outcome?: OutcomeRecord; ended?: Call["ended"] };
  const rows: Row[] = calls.map((c) => ({ id: c.id, real: c.real, tool: c.name, args: c.args ?? {}, ...(outcomeFor.has(c.id) ? { outcome: outcomeFor.get(c.id)! } : {}), ...(c.ended ? { ended: c.ended } : {}) }));
  extra.forEach((o, i) => rows.push({ id: str(o.callId) ?? `record-${i + 1}`, real: str(o.callId) !== undefined, tool: o.tool, args: { owner: o.owner, repo: o.repo }, outcome: o }));

  const steps: Step[] = [];
  let held = new Set<InfluenceClass>();
  rows.forEach((row, i) => {
    const evs = events.get(row.id) ?? [];
    const response = evs.find((e) => (e as Obj).type === "response") as Obj | undefined;
    const errorEvent = evs.find((e) => (e as Obj).type === "error") as Obj | undefined;
    const o = row.outcome;

    let result: Step["result"] | undefined;
    let reason: string | undefined;
    if (o) {
      if (o.verdict !== "ALLOWED") {
        result = "refused";
        reason = plainReason(o.verdict);
      } else if (o.isError) {
        result = "error";
        reason = "the tool returned an error";
      } else result = "allowed";
    } else if (response) {
      const verdict = str(response.verdict);
      if (verdict !== undefined && response.isError === true) {
        result = "refused";
        reason = plainReason(verdict);
      } else if (response.isError === true) {
        result = "error";
        reason = "the tool returned an error";
      } else result = "allowed";
    } else if (errorEvent) {
      result = "error";
      reason = `the call failed before the server answered${str(errorEvent.code) ? ` (${str(errorEvent.code)})` : ""}`;
    } else if (row.ended) {
      result = row.ended.isError ? "error" : "allowed";
      if (row.ended.isError) reason = "the tool returned an error";
    }

    const before = [...held];
    // what the agent holds after this call: the extension's running count when it logged one, else the call's own label
    const after = countsOf(response?.classes);
    if (after) held = new Set(after);
    else if (o && o.verdict === "ALLOWED" && o.label) held.add(o.label);

    if (result === undefined) {
      if (!opts.complete) return;
      result = "error";
      reason = "no answer was recorded before the run ended";
    }
    const rid = str(o?.rid) ?? str(response?.rid) ?? str((evs[0] as Obj | undefined)?.rid);
    const template = s.steps[row.tool];
    steps.push({
      index: i + 1,
      tool: row.tool,
      phrase: template !== undefined ? fill(template, row.args) : `use the ${row.tool} tool`,
      held: CLASS_ORDER.filter((c) => before.includes(c)).map((c) => PLAIN_CLASS[c]),
      result,
      ...(reason !== undefined ? { reason } : {}),
      evidence: { ...(row.real ? { callId: row.id } : {}), ...(rid !== undefined ? { rid } : {}), ...(o ? { outcome: o } : {}), events: evs, evidence: evidence.get(row.id) ?? [] },
    });
  });
  return steps;
}
