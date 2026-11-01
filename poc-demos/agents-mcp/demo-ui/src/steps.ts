// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { BUILTIN_LOCAL_TOOLS, type Scenario } from "../../mock-github-mcp/src/scenario.ts";
import {
  folderRuleFor, readAttestation, readChain, readInfluence, readLocalDecision, readLocalRules, readProof,
  type InfluenceClass, type InfluenceEntry, type LocalDecision, type LocalRules, type MerkleProof, type ResponseAttestation,
  type StampV3,
} from "@paztport/core";

/** One tool call, in plain words. `index` counts from 1 in the order the model made the calls. */
export type Step = {
  index: number;
  tool: string;
  phrase: string;
  /** What the agent had read before this call, in plain words. */
  held: string[];
  result: "allowed" | "refused" | "error";
  reason?: string;
  /** A refusal's reason code, e.g. INFLUENCE_DENIED. */
  code?: string;
  /** The rule behind a refusal, in plain words, when the code has one written. */
  rule?: string;
  /** A local tool call (pi's built-in tools): the rule that decided it, in plain words. */
  local?: LocalDetail;
  evidence: { callId?: string; rid?: string; outcome?: OutcomeRecord; events: unknown[]; evidence: ShownRecord[] };
};
/**
 * What the page shows of an evidence record's tokens, decoded: a call's or a local record's chain, a response's
 * attestation, a local record's influence and route proof. `unreadable` names each token that does not read.
 */
export type Display = {
  chain?: StampV3[];
  attestation?: ResponseAttestation;
  influence?: InfluenceEntry[];
  proof?: MerkleProof;
  unreadable?: string[];
};
/** An evidence record as a step shows it: the record, and its tokens decoded. */
export type ShownRecord = Record<string, unknown> & { display: Display };
/** What decided a local call, from the call's own evidence record and the rules in the evidence file's client record. */
export type LocalDetail = {
  verdict: string;
  /** Whether the session's route list had this tool. Absent when no evidence record was found. */
  routeAllowed?: boolean;
  /** One line per path or program the gate resolved: what it was and the rule that applied. */
  checks: { what: string; rule: string }[];
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
  INFLUENCE_DENIED: "a public write after the agent had read private data together with text from someone outside the project or content from an unverified source",
  UNSAFE_SESSION: "a write in a session that couldn't prove where its requests came from",
  PATH_NOT_ALLOWED: "outside what this session may do",
  SCOPE_DENIED: "outside what this session may do",
  UNCHECKABLE: "couldn't be checked",
  POLICY_EXPIRED: "the signed policy had expired, so nothing could pass until it was renewed",
};

export const PLAIN_RULE: Record<string, string> = {
  INFLUENCE_DENIED:
    "A write to a public repository is refused when what the agent has read so far includes private data together with text from someone outside the project or from an unverified source.",
  UNSAFE_SESSION: "A write is refused when the session could not prove where its requests came from.",
  PATH_NOT_ALLOWED: "A local action is refused when it touches a folder or program that the session's rules do not allow for that kind of action.",
  SCOPE_DENIED: "A local action is refused when it touches a folder or program that the session's rules do not allow for that kind of action.",
  UNCHECKABLE: "A command is refused when Paztport can't tell what it would do. The check is conservative: simple commands with plain paths are the ones it can read.",
  POLICY_EXPIRED:
    "Every call is refused once the signed policy it is checked against has expired. That is a configuration failure, not a sign of an attack: the policy has to be renewed before anything can pass.",
};
/** The influence rule as it reads for a local write. */
const LOCAL_INFLUENCE_RULE =
  "A write to a public folder is refused when what the agent has read so far includes private data together with text from someone outside the project or from an unverified source.";

/** The plain reason for a refusal code; a code without its own wording reads `refused: <CODE>`. */
export function plainReason(code: string): string {
  return PLAIN_REASON[code] ?? `refused: ${code}`;
}

/** Read order for `held`, so the same classes always come out in the same order. */
const CLASS_ORDER: readonly InfluenceClass[] = ["private", "third-party", "local-untrusted", "public"];
/** Public content is not worth listing as something the agent "already held". */
const HELD_ORDER: readonly InfluenceClass[] = CLASS_ORDER.filter((c) => c !== "public");
/** Phrases for a call whose argument has a known meaning when it is empty. */
const EMPTY_ARG_PHRASES: Record<string, { arg: string; phrase: string }> = {
  get_file_contents: { arg: "path", phrase: "read the top level of {owner}/{repo}" },
};
const MAX_ARG_CHARS = 80;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);

type Call = { id: string; real: boolean; name: string; local?: true; args?: Obj; ended?: { isError: boolean } };

/** pi names a tool mcp__<server>__<tool>, with every character outside [A-Za-z0-9_] replaced by "_". */
function toolOf(full: string, serverId: string): string | undefined {
  const prefix = `mcp__${serverId}__`.replace(/[^A-Za-z0-9_]/g, "_");
  if (full.startsWith(prefix)) return full.slice(prefix.length);
  const m = /^mcp__[A-Za-z0-9]+__(.+)$/.exec(full);
  return m ? m[1] : undefined;
}

/** The MCP tool calls, and for a local-tools scenario pi's built-in tool calls, in a pi `--mode json` transcript, in the order they first appear. */
function callsOf(transcript: unknown[], s: Scenario): Call[] {
  const byId = new Map<string, Call>();
  const upsert = (id: string | undefined, line: number, fullName: unknown): Call | undefined => {
    const mcp = typeof fullName === "string" ? toolOf(fullName, s.serverId) : undefined;
    const local = mcp === undefined && s.localTools === true && typeof fullName === "string" && BUILTIN_LOCAL_TOOLS.includes(fullName);
    const name = mcp ?? (local ? (fullName as string) : undefined);
    const key = id ?? `line-${line}`;
    const existing = byId.get(key);
    if (existing) return existing;
    if (name === undefined) return undefined;
    const call: Call = { id: key, real: id !== undefined, name, ...(local ? { local: true as const } : {}) };
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

/** An argument as it goes into a phrase, or undefined when it is missing or blank. */
function argText(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  const s = (typeof v === "string" ? v : JSON.stringify(v)).replace(/\s+/g, " ").trim();
  if (s === "") return undefined;
  return s.length > MAX_ARG_CHARS ? `${s.slice(0, MAX_ARG_CHARS)}…` : s;
}

const placeholders = (template: string): string[] => [...template.matchAll(/\{([^{}]*)\}/g)].map((m) => m[1]!);
const fill = (template: string, args: Obj): string => template.replace(/\{([^{}]*)\}/g, (_m, key: string) => argText(args[key])!);
const complete = (template: string, args: Obj): boolean => placeholders(template).every((k) => argText(args[k]) !== undefined);

/**
 * The plain phrase for a call: the scenario's template when every argument it names is there; otherwise a
 * phrase that leaves the missing argument out, so a phrase never has a gap or a dangling word.
 */
function phraseFor(s: Scenario, tool: string, args: Obj): string {
  const template = s.steps[tool];
  if (template !== undefined && complete(template, args)) return fill(template, args);
  const known = EMPTY_ARG_PHRASES[tool];
  if (template !== undefined && known && argText(args[known.arg]) === undefined && complete(known.phrase, args)) return fill(known.phrase, args);
  const where = argText(args.owner) !== undefined && argText(args.repo) !== undefined ? ` on ${argText(args.owner)}/${argText(args.repo)}` : "";
  return `use the ${tool} tool${where}`;
}

/**
 * The plain phrase for a call by its full pi tool name, as the step rows say it, or undefined when the tool is not
 * one the scenario has a step for. The model chooses the name, so a name the scenario does not know is never shown.
 */
export function callPhrase(s: Scenario, fullName: string, args: Obj): string | undefined {
  const tool = toolOf(fullName, s.serverId) ?? (s.localTools === true && BUILTIN_LOCAL_TOOLS.includes(fullName) ? fullName : undefined);
  return tool === undefined || !Object.hasOwn(s.steps, tool) ? undefined : phraseFor(s, tool, args);
}

/**
 * The agent's final answer: the text of the last assistant message in a pi `--mode json` transcript.
 * Thinking is left out. A run whose last assistant message is a tool call has no final answer.
 */
export function finalAnswer(transcript: unknown[]): string | undefined {
  for (let i = transcript.length - 1; i >= 0; i--) {
    const ev = transcript[i];
    if (!isObj(ev) || ev.type !== "message_end" || !isObj(ev.message) || ev.message.role !== "assistant") continue;
    const content = Array.isArray(ev.message.content) ? ev.message.content.filter(isObj) : [];
    if (content.some((c) => c.type === "toolCall")) return undefined;
    const text = content
      .filter((c) => c.type === "text" && typeof c.text === "string")
      .map((c) => c.text as string)
      .join("\n\n")
      .trim();
    return text === "" ? undefined : text;
  }
  return undefined;
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
  const calls = callsOf(logs.transcript, s);
  const rules = s.localTools === true ? clientRules(logs.evidence) : undefined;
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
  const waiting = calls.filter((c) => !c.local && !outcomeFor.has(c.id) && !hasErrorEvent(c.id));
  // a record that names a call the transcript lacks is not part of the by-order pairing
  // each call takes the first unmatched record of the same tool, so calls that reached the server in another order still pair up
  const orderPool = spare.filter((o) => typeof o.callId !== "string");
  for (const c of waiting) {
    const at = orderPool.findIndex((o) => o.tool === c.name);
    if (at < 0) continue;
    const [o] = orderPool.splice(at, 1);
    outcomeFor.set(c.id, o!);
    taken.add(o!);
  }
  // records nothing in the transcript accounts for
  const extra = outcomes.filter((o) => !taken.has(o));

  type Row = { id: string; real: boolean; tool: string; local?: true; args: Obj; outcome?: OutcomeRecord; ended?: Call["ended"] };
  const rows: Row[] = calls.map((c) => ({ id: c.id, real: c.real, tool: c.name, ...(c.local ? { local: true as const } : {}), args: c.args ?? {}, ...(outcomeFor.has(c.id) ? { outcome: outcomeFor.get(c.id)! } : {}), ...(c.ended ? { ended: c.ended } : {}) }));
  extra.forEach((o, i) => rows.push({ id: str(o.callId) ?? `record-${i + 1}`, real: str(o.callId) !== undefined, tool: o.tool, args: { owner: o.owner, repo: o.repo }, outcome: o }));

  const steps: Step[] = [];
  let held = new Set<InfluenceClass>();
  rows.forEach((row, i) => {
    const evs = events.get(row.id) ?? [];
    const response = evs.find((e) => (e as Obj).type === "response") as Obj | undefined;
    const errorEvent = evs.find((e) => (e as Obj).type === "error") as Obj | undefined;
    const o = row.outcome;

    const localEvent = row.local ? (evs.find((e) => (e as Obj).type === "local") as Obj | undefined) : undefined;
    const localRecord = row.local ? (evidence.get(row.id) ?? []).find((e) => (e as Obj).type === "local") as Obj | undefined : undefined;

    let result: Step["result"] | undefined;
    let reason: string | undefined;
    let code: string | undefined;
    if (localEvent) {
      const verdict = str(localEvent.verdict);
      if (verdict !== undefined && verdict !== "OK") {
        result = "refused";
        code = verdict;
        reason = plainReason(verdict);
      } else if (row.ended?.isError) {
        result = "error";
        reason = "the tool returned an error";
      } else result = "allowed";
    } else if (o) {
      if (o.verdict !== "ALLOWED") {
        result = "refused";
        code = o.verdict;
        reason = plainReason(o.verdict);
      } else if (o.isError) {
        result = "error";
        reason = "the tool returned an error";
      } else result = "allowed";
    } else if (response) {
      const verdict = str(response.verdict);
      if (verdict !== undefined && response.isError === true) {
        result = "refused";
        code = verdict;
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

    // a local call's record carries what the agent held when it was decided
    const recordedInfluence = localRecord !== undefined ? display(localRecord).influence : undefined;
    const recorded = recordedInfluence !== undefined ? new Set(recordedInfluence.map((e) => e.cls)) : undefined;
    if (recorded) held = new Set(CLASS_ORDER.filter((c) => recorded.has(c)));
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
    steps.push({
      index: i + 1,
      tool: row.tool,
      phrase: phraseFor(s, row.tool, row.args),
      held: HELD_ORDER.filter((c) => before.includes(c)).map((c) => PLAIN_CLASS[c]),
      result,
      ...(reason !== undefined ? { reason } : {}),
      ...(code !== undefined ? { code, ...(PLAIN_RULE[code] !== undefined ? { rule: row.local && code === "INFLUENCE_DENIED" ? LOCAL_INFLUENCE_RULE : PLAIN_RULE[code] } : {}) } : {}),
      ...(row.local ? { local: localDetail(localEvent, localRecord, rules) } : {}),
      evidence: { ...(row.real ? { callId: row.id } : {}), ...(rid !== undefined ? { rid } : {}), ...(o ? { outcome: o } : {}), events: evs, evidence: (evidence.get(row.id) ?? []).map(shown) },
    });
  });
  return steps;
}

/** The rules in the evidence file's client record (the latest one), or undefined when there is none or they don't read. */
function clientRules(evidence: unknown[]): LocalRules | undefined {
  for (let i = evidence.length - 1; i >= 0; i--) {
    const r = evidence[i];
    if (!isObj(r) || r.type !== "client") continue;
    return typeof r.rules === "string" ? readOr(() => readLocalRules(r.rules as string)) : undefined;
  }
  return undefined;
}

/** What `read` gives, or undefined when it throws. */
function readOr<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/** A token an evidence record holds: the name the page shows for it, its reader, and where the display keeps its value. */
type HeldToken = { name: string; token: unknown; read: (token: string) => unknown; into: keyof Display };

/** The tokens a record holds that the page shows. */
function tokensOf(r: Obj): HeldToken[] {
  const meta = (v: unknown): Obj => (isObj(v) && isObj(v._meta) ? v._meta : {});
  switch (r.type) {
    case "call":
      return [{ name: "paztport/chain", token: meta(r.params)["paztport/chain"], read: readChain, into: "chain" }];
    case "response": {
      const token = meta(r.result)["paztport/attestation"];
      return token === undefined ? [] : [{ name: "paztport/attestation", token, read: readAttestation, into: "attestation" }];
    }
    case "local":
      return [
        { name: "chain", token: r.chain, read: readChain, into: "chain" },
        { name: "influence", token: r.influence, read: readInfluence, into: "influence" },
        ...(r.proof === null ? [] : [{ name: "proof", token: r.proof, read: readProof, into: "proof" } as const]),
      ];
  }
  return [];
}

/** An evidence record's tokens, decoded with the SDK's readers; a token that does not read is named in `unreadable`. */
function display(r: Obj): Display {
  const out: Record<string, unknown> = {};
  const unreadable: string[] = [];
  for (const { name, token, read, into } of tokensOf(r)) {
    const value = typeof token === "string" ? readOr(() => read(token)) : undefined;
    if (value === undefined) unreadable.push(name);
    else out[into] = value;
  }
  return { ...(out as Display), ...(unreadable.length > 0 ? { unreadable } : {}) };
}

/** An evidence record as a step shows it. */
function shown(r: unknown): ShownRecord {
  const rec = r as Obj;
  return { ...rec, display: display(rec) };
}

/** A local record's decision, or undefined when it does not read. */
function decisionOf(record: Obj | undefined): LocalDecision | undefined {
  return typeof record?.decision === "string" ? readOr(() => readLocalDecision(record.decision as string)) : undefined;
}

const NEED_WORD: Record<string, string> = { read: "read", write: "write to", exec: "run a program in" };
const VIA_RULE: Record<string, string> = {
  list: "a program on the session's list",
  folder: "a program from a folder the session may run programs from",
  never: "a program that can run other programs, write anywhere or reach the network, so it is never allowed",
  missing: "a program that was not found",
  uncheckable: "a program that couldn't be checked",
};

/** The rule that applied to each path and program the gate resolved, in plain words, from the call's own record and the signed rules. */
function localDetail(event: Obj | undefined, record: Obj | undefined, rules: LocalRules | undefined): LocalDetail {
  const checks: LocalDetail["checks"] = [];
  const decision = decisionOf(record);
  for (const p of decision?.resolved.paths ?? []) {
    const what = `${NEED_WORD[p.need] ?? p.need} ${p.at}`;
    const folder = rules ? folderRuleFor(p.at, rules) : undefined;
    if (folder) {
      const parts = [`the folder ${folder.path} allows ${folder.access.join(" and ")}`];
      if (folder.destination !== undefined) parts.push(`writes there count as ${folder.destination}`);
      if (folder.label !== undefined) parts.push(`what is read there is ${folder.label}`);
      checks.push({ what, rule: parts.join("; ") });
    } else if (p.at === "outside") checks.push({ what, rule: "outside every folder this session may use" });
    else if (p.at === "refused") checks.push({ what, rule: "a folder this session may not use" });
    else if (p.at === "uncheckable") checks.push({ what, rule: "a path that couldn't be checked" });
    else checks.push({ what, rule: "no folder rule covers it" });
  }
  for (const g of decision?.resolved.programs ?? []) {
    checks.push({ what: `run ${g.name}`, rule: VIA_RULE[g.via] ?? "not on the session's list" });
  }
  return {
    verdict: str(event?.verdict) ?? decision?.verdict ?? "unknown",
    ...(decision !== undefined ? { routeAllowed: decision.routeAllowed } : {}),
    checks,
  };
}
