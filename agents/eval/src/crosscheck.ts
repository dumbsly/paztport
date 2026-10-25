// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { readdirSync } from "node:fs";
import { loadScenario, type Scenario } from "../../mock-github-mcp/src/scenario.ts";
import { usableRecords } from "./eval.ts";
import { readLocalFacts, scoreRunFile } from "./score.ts";
import { NOT_FAILURES, signedEvidenceNeeded, verifyEvidence, type VerifyReport } from "./verify.ts";
import type { RunMode, RunResult } from "./runner.ts";

/**
 * What the eval concludes about one run's evidence.
 * - ok: the evidence file verified, and it agrees with the outcome log.
 * - failed: it did not verify, is missing when it should exist, or disagrees with the outcome log.
 * - none: nothing to check, and nothing was expected (the modes without Paztport).
 * - not-recorded: a run with Paztport on that ended in error or timed out before anything was recorded (its outcome
 *   log is usable and shows no signed call), so there is no evidence.
 */
export type RunVerify = { status: "ok" | "failed" | "none" | "not-recorded"; problems: string[] };

/** `verify` reads what is in an evidence file; it cannot see a file that was removed or emptied. These checks can. */
const EXPECT_EVIDENCE: readonly RunMode[] = ["on", "clean-on"];
const MAX_PROBLEMS = 10;

/**
 * True when the file exists, has bytes in it, and is not one `verify` reports as NOTHING TO CHECK (only the
 * unsigned run record and the client record: Paztport off, or on and ended before a session). The eval, the page and the CLI all
 * decide this the same way, from verifyEvidence.
 */
export function hasEvidenceFile(path: string): boolean {
  try {
    if (statSync(path).size === 0) return false;
  } catch {
    return false;
  }
  return verifyEvidence(path).nothingToCheck !== true;
}

type Ids = { rid: string; callId: string };
const key = (i: Ids) => JSON.stringify([i.rid, i.callId]);

/** rid and callId by line number of an evidence file (the same numbering `verify` reports). */
function idsByLine(path: string): Map<number, Ids> {
  const out = new Map<number, Ids>();
  readFileSync(path, "utf8")
    .split("\n")
    .forEach((raw, i) => {
      if (raw.trim() === "") return;
      try {
        const r: unknown = JSON.parse(raw);
        if (typeof r === "object" && r !== null) {
          const o = r as Record<string, unknown>;
          if (typeof o.rid === "string" && typeof o.callId === "string") out.set(i + 1, { rid: o.rid, callId: o.callId });
        }
      } catch {
        // verify reports unreadable lines
      }
    });
  return out;
}

/** A `local` line of the extension's events log (it carries no content: tool, call id, rid, verdict). */
type LocalEvent = { line: number; tool: unknown; callId: unknown; rid: unknown; verdict: unknown };

/**
 * The `local` lines of a run's events log. A missing log has none. One that exists but can't be read, or has a
 * line that is not a JSON object, can't show which local calls were made, so it comes back as a problem.
 */
function readLocalEvents(path: string): LocalEvent[] | { problem: string } {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    return { problem: `the events log can't be read (${(e as Error).message})` };
  }
  const out: LocalEvent[] = [];
  for (const [i, raw] of text.split("\n").entries()) {
    if (raw.trim() === "") continue;
    let ev: unknown;
    try {
      ev = JSON.parse(raw);
    } catch {
      return { problem: `the events log can't be read (line ${i + 1} is not valid JSON)` };
    }
    if (typeof ev !== "object" || ev === null || Array.isArray(ev)) return { problem: `the events log can't be read (line ${i + 1} is not an event)` };
    const o = ev as Record<string, unknown>;
    if (o.type === "local") out.push({ line: i + 1, tool: o.tool, callId: o.callId, rid: o.rid, verdict: o.verdict });
  }
  return out;
}

/**
 * True when a local event was made during a run (it has a rid). In enforce mode the gate signs every such call;
 * in no-root mode it emits them unsigned, but the eval never runs no-root: its modes with Paztport on are enforce.
 */
const inRun = (e: LocalEvent): boolean => typeof e.rid === "string";

/** The parsed records of an evidence file, by line number (the same numbering `verify` reports). */
function recordsByLine(path: string): Map<number, Record<string, unknown>> {
  const out = new Map<number, Record<string, unknown>>();
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return out;
  }
  text.split("\n").forEach((raw, i) => {
    if (raw.trim() === "") return;
    try {
      const r: unknown = JSON.parse(raw);
      if (typeof r === "object" && r !== null && !Array.isArray(r)) out.set(i + 1, r as Record<string, unknown>);
    } catch {
      // verify reports unreadable lines
    }
  });
  return out;
}

const decision = (verdict: string): string => (verdict === "OK" ? "allowed" : `refused (${verdict})`);

/**
 * Cross-checks the events log's local lines (what the eval counts local blocks and scope refusals from) against
 * the verified local records. Every local event made during a run must match a verified local record with the
 * same call id, tool and verdict, and every verified local record must have its event, so a local block counts
 * only when its signed refusal verified. A local event outside a run is unsigned by design, and the gate refuses
 * every call there as out of scope, so it must be SCOPE_DENIED. A run with Paztport on is in enforce mode, which
 * writes the client record before any local call, so local events made during a run need one. A call that the
 * gate allowed and something later stopped (another handler, an abort) has an OK record and an OK event; that
 * is not a disagreement.
 *
 * Local steps are signed by the client alone, so a genuine step could be copied from another run made with the
 * same keys. When the outcome log shows attested calls, each local record's rid must be one the server saw in
 * this run; reusedLocalSignatures covers the folder as a whole.
 */
function crossCheckLocal(events: LocalEvent[], report: VerifyReport, evidencePath: string, records: OutcomeRecord[] | null): string[] {
  const problems: string[] = [];
  const byLine = recordsByLine(evidencePath);
  const hasClient = report.items.some((i) => i.type === "client");
  const verified = new Map<string, { tool: string; verdict: string; callId: string }>();
  for (const item of report.items) {
    const rec = byLine.get(item.line);
    if (item.type !== "local" || rec === undefined || (item.result !== "OK" && item.result !== "REFUSED")) continue;
    if (typeof rec.rid === "string" && typeof rec.callId === "string" && typeof rec.tool === "string" && typeof rec.verdict === "string") {
      verified.set(key({ rid: rec.rid, callId: rec.callId }), { tool: rec.tool, verdict: rec.verdict, callId: rec.callId });
    }
  }

  const witnessed = new Set((records ?? []).filter((r) => typeof r.sess === "string" && typeof r.rid === "string").map((r) => r.rid as string));
  if (witnessed.size > 0) {
    for (const rec of byLine.values()) {
      if (rec.type === "local" && typeof rec.rid === "string" && !witnessed.has(rec.rid)) {
        problems.push(`evidence.jsonl has a local record for call ${String(rec.callId)} in a run the server never saw`);
      }
    }
  }

  const shown = new Set<string>();
  let noClient = false;
  for (const e of events) {
    if (!inRun(e)) {
      if (e.verdict !== "SCOPE_DENIED") {
        problems.push(`the events log shows local call ${String(e.callId)} outside a run with verdict ${String(e.verdict)}; outside a run the gate refuses every call as out of scope`);
      }
      continue;
    }
    if (typeof e.callId !== "string" || typeof e.verdict !== "string") {
      problems.push(`the events log has a local line (line ${e.line}) with no call id or verdict`);
      continue;
    }
    const k = key({ rid: e.rid as string, callId: e.callId });
    if (shown.has(k)) {
      problems.push(`the events log shows local call ${e.callId} twice`);
      continue;
    }
    shown.add(k);
    if (!hasClient) {
      noClient = true;
      continue;
    }
    const rec = verified.get(k);
    if (rec === undefined) {
      problems.push(`the events log shows local call ${e.callId} (${String(e.tool)}) ${decision(e.verdict)}, which has no verified local record in evidence.jsonl`);
    } else if (rec.tool !== e.tool) {
      problems.push(`the events log shows local call ${e.callId} as ${String(e.tool)}, but evidence.jsonl shows ${rec.tool}`);
    } else if (rec.verdict !== e.verdict) {
      problems.push(`the events log shows local call ${e.callId} ${decision(e.verdict)}, but evidence.jsonl shows it ${decision(rec.verdict)}`);
    }
  }
  if (noClient) problems.push("the events log shows local tool calls during a run, but evidence.jsonl has no client record");
  for (const [k, rec] of verified) {
    if (!shown.has(k)) problems.push(`evidence.jsonl has a local record for call ${rec.callId} (${rec.tool}) that the events log does not show`);
  }
  return problems;
}

/** True when the evidence has a client record that verified and carries local rules. */
function hasClientWithRules(report: VerifyReport, evidencePath: string): boolean {
  const byLine = recordsByLine(evidencePath);
  return report.items.some((i) => i.type === "client" && i.result === "OK" && byLine.get(i.line)?.rules !== null && byLine.get(i.line)?.rules !== undefined);
}

/**
 * Signed local steps that appear in more than one run of a results folder. Each run's local origin stamps are
 * minted for its own run, and each step stamp is unique, so the same signature in two runs means a step was
 * copied from one into the other. `evidence` maps each run (its folder, as reported) to its evidence file; files
 * that are missing or can't be read have nothing to compare. Returns the problems by run, only for runs with any.
 */
export function reusedLocalSignatures(evidence: Map<string, string>): Map<string, string[]> {
  const owners = new Map<string, Set<string>>(); // signature -> runs
  for (const [run, path] of evidence) {
    for (const rec of recordsByLine(path).values()) {
      if (rec.type !== "local" || !Array.isArray(rec.chain)) continue;
      for (const stamp of rec.chain.slice(0, 2)) {
        const sig = typeof stamp === "object" && stamp !== null ? (stamp as Record<string, unknown>).sig : undefined;
        if (typeof sig !== "string") continue;
        const set = owners.get(sig) ?? new Set<string>();
        set.add(run);
        owners.set(sig, set);
      }
    }
  }
  const pairs = new Map<string, Set<string>>(); // run -> the other runs it shares a signature with
  for (const runs of owners.values()) {
    if (runs.size < 2) continue;
    for (const run of runs) for (const other of runs) if (other !== run) pairs.set(run, (pairs.get(run) ?? new Set<string>()).add(other));
  }
  const out = new Map<string, string[]>();
  for (const [run, others] of pairs) out.set(run, [...others].sort().map((o) => `a signed local step in evidence.jsonl also appears in ${o}'s evidence`));
  return out;
}

/** A run's check with more problems added: any problem fails it. A list already capped keeps one count of what it hides. */
export function withProblems(v: RunVerify, more: string[] | undefined): RunVerify {
  if (more === undefined || more.length === 0) return v;
  const tail = v.problems.length === MAX_PROBLEMS + 1 ? /^and (\d+) more$/.exec(v.problems[MAX_PROBLEMS]!) : null;
  const shown = [...(tail !== null ? v.problems.slice(0, MAX_PROBLEMS) : v.problems), ...more];
  const hidden = (tail !== null ? Number(tail[1]) : 0) + Math.max(0, shown.length - MAX_PROBLEMS);
  return { status: "failed", problems: hidden > 0 ? [...shown.slice(0, MAX_PROBLEMS), `and ${hidden} more`] : shown };
}

/** Cross-checks the verified evidence against the outcome log. Returns the disagreements. */
function crossCheck(records: OutcomeRecord[], report: VerifyReport, evidencePath: string): string[] {
  const problems: string[] = [];
  const ids = idsByLine(evidencePath);
  const verifiedCalls = new Set<string>();
  const answered = new Set<string>();
  const refused = new Set<string>();
  for (const item of report.items) {
    const id = ids.get(item.line);
    if (id === undefined) continue;
    if (item.type === "call" && item.result === "OK") verifiedCalls.add(key(id));
    if (item.type === "response" && (item.result === "OK" || item.result === "REFUSED")) {
      answered.add(key(id));
      if (item.result === "REFUSED") refused.add(key(id));
    }
  }

  const attested = new Map<string, OutcomeRecord>();
  for (const r of records) {
    if (typeof r.sess !== "string") continue;
    if (typeof r.rid !== "string" || typeof r.callId !== "string") {
      problems.push(`an outcome record for ${r.tool} has a session but no call id`);
      continue;
    }
    const k = key({ rid: r.rid, callId: r.callId });
    if (attested.has(k)) problems.push(`the outcome log shows call ${r.callId} twice`);
    attested.set(k, r);
    if (!verifiedCalls.has(k)) problems.push(`the outcome log shows call ${r.callId} (${r.tool}), which has no verified call in evidence.jsonl`);
  }
  for (const k of answered) {
    if (!attested.has(k)) problems.push(`evidence.jsonl has a response to call ${(JSON.parse(k) as string[])[1]} that the outcome log does not show`);
  }
  for (const k of refused) {
    const r = attested.get(k);
    if (r !== undefined && r.verdict === "ALLOWED") problems.push(`evidence.jsonl shows a refusal of call ${r.callId}, but the outcome log shows it allowed`);
  }
  for (const [k, r] of attested) {
    if (r.verdict !== "ALLOWED" && answered.has(k) && !refused.has(k)) {
      problems.push(`the outcome log shows call ${r.callId} refused (${r.verdict}), but evidence.jsonl shows a response that was not a refusal`);
    }
  }
  return problems;
}

/**
 * Decides one run's verification status.
 * @param records the run's outcome records, or null when the log could not be read or used
 * @param report the verify report for the run's evidence file, or undefined when it is missing or empty
 * @param expectedPin the fingerprint of this eval's server policy public key. Undefined only for an older demo
 *   single run, which recorded none: the pins are then not compared.
 * @param eventsPath the run's events log. Read only in the modes with Paztport on, as the score reads it: its
 *   local lines are cross-checked against the evidence's local records (see crossCheckLocal).
 */
export function checkRun(input: {
  mode: RunMode;
  /** The scored outcome. A run scored "error" or "timeout" with Paztport on and nothing recorded is not held against its missing evidence. */
  outcome: string;
  records: OutcomeRecord[] | null;
  evidencePath: string;
  eventsPath: string;
  report: VerifyReport | undefined;
  expectedPin: string | undefined;
  /** The scenario gives the model local tools: a run with Paztport on must then have a verified client record with local rules. */
  localTools?: boolean;
  /** Whose server key the expected pin is, as a failure names it. Default "this eval's"; a demo single run is "the demo's". */
  pinOwner?: string;
}): RunVerify {
  const { mode, outcome, records, report, expectedPin } = input;
  const problems: string[] = [];
  const attested = records?.some((r) => typeof r.sess === "string") ?? false;
  const events = EXPECT_EVIDENCE.includes(mode) ? readLocalEvents(input.eventsPath) : [];
  const eventsProblem = Array.isArray(events) ? undefined : events.problem;
  const localDuringRun = Array.isArray(events) && events.some(inRun);

  if (report === undefined || report.nothingToCheck === true) {
    if (attested) problems.push("the outcome log shows attested calls, but evidence.jsonl is missing, empty or has no signed records");
    else if (localDuringRun) problems.push("the events log shows local tool calls during a run, but evidence.jsonl is missing, empty or has no signed records");
    else if (eventsProblem !== undefined) problems.push(`${eventsProblem}, so it can't show that this run made no local tool calls`);
    else if (EXPECT_EVIDENCE.includes(mode)) {
      // Only a run that ended early (error or timeout) with a usable log showing no signed call may have
      // nothing recorded. A log that can't be used can't show that, so the missing evidence counts against it.
      if ((outcome === "error" || outcome === "timeout") && records !== null) return { status: "not-recorded", problems: [] };
      if (records === null) problems.push("the outcome log could not be used, and evidence.jsonl is missing, empty or has no signed records");
      else problems.push(existsSync(input.evidencePath) && statSync(input.evidencePath).size > 0 ? "a run with Paztport on, but evidence.jsonl has no signed records" : "a run with Paztport on has no evidence.jsonl");
    }
    return { status: problems.length > 0 ? "failed" : "none", problems };
  }

  if (!report.ok) {
    const bad = report.items.find((i) => !NOT_FAILURES.includes(i.result));
    problems.push(bad === undefined ? "evidence.jsonl did not verify" : `evidence.jsonl line ${bad.line}: ${bad.type} ${bad.result}`);
  }
  for (const p of report.pins) {
    if (expectedPin !== undefined && p !== expectedPin) problems.push(`evidence.jsonl is pinned to server key ${p}, not ${input.pinOwner ?? "this eval's"} server key ${expectedPin}`);
  }
  if (report.pins.length === 0 && (attested || EXPECT_EVIDENCE.includes(mode))) problems.push("evidence.jsonl has no verified session");
  if (records === null) problems.push("the outcome log could not be used, so the evidence could not be compared with it");
  else problems.push(...crossCheck(records, report, input.evidencePath));
  if (eventsProblem !== undefined) problems.push(`${eventsProblem}, so its local tool calls could not be compared with evidence.jsonl`);
  else problems.push(...crossCheckLocal(events as LocalEvent[], report, input.evidencePath, records));
  if (input.localTools === true && EXPECT_EVIDENCE.includes(mode) && !hasClientWithRules(report, input.evidencePath)) {
    problems.push("a local-tools run with Paztport on, but evidence.jsonl has no verified client record with local rules");
  }

  const capped = problems.length > MAX_PROBLEMS ? [...problems.slice(0, MAX_PROBLEMS), `and ${problems.length - MAX_PROBLEMS} more`] : problems;
  return { status: problems.length > 0 ? "failed" : "ok", problems: capped };
}

const MODES: readonly string[] = ["off", "on", "clean-off", "clean-on", "warning"];

/** A demo single-run folder: its run files and demo-run.json at the top, and no runs/ folder (an eval's). */
export function isSingleRunDir(dir: string): boolean {
  return existsSync(join(dir, "demo-run.json")) && !existsSync(join(dir, "runs"));
}

export type SingleRunCheck = {
  /** The run's evidence.jsonl, labelled with its path in the folder. */
  report: VerifyReport;
  crossCheck: RunVerify;
  /** demo-run.json records no server key, and the evidence has pins, so they were not compared with one. */
  noServerKey?: true;
  /**
   * The outcome demo-run.json records, and the outcome the run's files score now (as the demo scored it), or
   * why it was not scored again. Absent when demo-run.json or run.json can't be read (the cross-check fails).
   */
  outcome?: { stored: string; rescored: string } | { stored: string; notRescored: string };
};

const SCENARIOS_DIR = join(import.meta.dirname, "../../scenarios");

/** The shipped scenario with this id (agents/scenarios/<folder>), or undefined when none has it. */
function findScenario(id: string): Scenario | undefined {
  let names: string[];
  try {
    names = readdirSync(SCENARIOS_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return undefined;
  }
  for (const name of names) {
    try {
      const scenario = loadScenario(join(SCENARIOS_DIR, name));
      if (scenario.id === id) return scenario;
    } catch {
      // a folder that does not load is not this scenario
    }
  }
  return undefined;
}

const STATUSES: readonly string[] = ["completed", "timeout", "error"];

/**
 * Scores a single run again from its files, with the call the demo makes when it saves the run: its outcome
 * log, run.json's result and its transcript, and for a scenario with local tools what its workspace and events
 * log show (readLocalFacts, with canary.txt and the mode). Returns the outcome, or why it can't be scored.
 */
function rescore(dir: string, scenarioId: unknown, scenario: Scenario | undefined, mode: RunMode): { rescored: string } | { notRescored: string } | undefined {
  const run = readObject(join(dir, "run.json"));
  if (run === undefined) return undefined; // the cross-check says run.json can't be read
  if (typeof scenarioId !== "string") return { notRescored: "demo-run.json names no scenario" };
  if (scenario === undefined) return { notRescored: `no scenario ${JSON.stringify(scenarioId)} in agents/scenarios` };
  if (!STATUSES.includes(run.status as string)) return { notRescored: "run.json records no status" };
  let canary = "";
  try {
    canary = readFileSync(join(dir, "canary.txt"), "utf8").trim();
  } catch {
    // only the scenario's markers are looked for
  }
  const result: RunResult = { status: run.status as RunResult["status"], exitCode: typeof run.exitCode === "number" ? run.exitCode : null, durationMs: 0, canary, mode };
  const local = scenario.localTools === true ? readLocalFacts(dir, scenario, canary, mode) : undefined;
  return { rescored: scoreRunFile(join(dir, "outcome.jsonl"), result, 1, ".", join(dir, "transcript.jsonl"), local).outcome };
}

/**
 * Checks a demo single-run folder as the eval checks each of its runs: its evidence.jsonl is verified, then
 * checkRun compares the events log, the outcome log and the evidence, and the evidence's pin with the server
 * key fingerprint, using the mode and scored outcome demo-run.json records; the run has local tools when
 * demo-run.json, config.json (a client policy) or the scenario it names says so. demo-run.json can be
 * edited, so it is not trusted on its own: whatever mode it records, a run whose outcome log shows signed
 * calls or whose events log shows local tool calls made during a run must have signed evidence (as
 * verifyResultsDir decides it), and its mode must be the one run.json and config.json record. A demo-run.json
 * without serverKey (written before the demo recorded it) is checked without the pin comparison.
 */
export function verifySingleRunDir(dir: string): SingleRunCheck {
  const evidencePath = join(dir, "evidence.jsonl");
  // a missing or empty file has nothing to check, as in a results folder: the runner creates it empty for a run
  // with Paztport on, so a run that ended before a session leaves it so; checkRun decides whether that may be
  let size: number | undefined;
  try {
    size = statSync(evidencePath).size;
  } catch {
    size = undefined;
  }
  const report: VerifyReport =
    size === undefined || size === 0 ? { file: "evidence.jsonl", ok: true, items: [], pins: [], nothingToCheck: true } : { ...verifyEvidence(evidencePath), file: "evidence.jsonl" };

  let run: unknown;
  try {
    run = JSON.parse(readFileSync(join(dir, "demo-run.json"), "utf8"));
  } catch (e) {
    return { report, crossCheck: { status: "failed", problems: [`demo-run.json can't be read (${(e as Error).message})`] } };
  }
  const obj = typeof run === "object" && run !== null && !Array.isArray(run) ? (run as Record<string, unknown>) : {};
  const scored = obj.scored;
  const outcome = typeof scored === "object" && scored !== null ? (scored as Record<string, unknown>).outcome : undefined;
  if (typeof obj.mode !== "string" || !MODES.includes(obj.mode) || typeof outcome !== "string") {
    return { report, crossCheck: { status: "failed", problems: ["demo-run.json can't be read (it has no mode or no scored outcome)"] } };
  }
  const key = obj.serverKey;
  const fingerprint = typeof key === "object" && key !== null ? (key as Record<string, unknown>).fingerprint : undefined;
  const scenarioId = typeof obj.scenario === "object" && obj.scenario !== null ? (obj.scenario as Record<string, unknown>).id : undefined;
  const scenario = typeof scenarioId === "string" ? findScenario(scenarioId) : undefined;
  const config = readObject(join(dir, "config.json"));
  let crossCheck = checkRun({
    mode: obj.mode as RunMode,
    outcome,
    records: usableRecords(join(dir, "outcome.jsonl")),
    evidencePath,
    eventsPath: join(dir, "events.jsonl"),
    report: report.nothingToCheck === true ? undefined : report,
    expectedPin: typeof fingerprint === "string" ? fingerprint : undefined,
    // demo-run.json can be edited: the runner's config (a client policy for local tools) and the scenario say so too
    localTools: obj.localTools === true || typeof config?.clientPolicyDir === "string" || scenario?.localTools === true,
    pinOwner: "the demo's",
  });
  // what demo-run.json says is not trusted on its own: the run's own logs say whether it must have signed evidence
  if (report.nothingToCheck === true && crossCheck.status !== "failed") {
    const need = signedEvidenceNeeded(dir);
    if (need !== undefined) crossCheck = { status: "failed", problems: [need] };
  }
  crossCheck = withProblems(crossCheck, modeDisagreements(dir, obj.mode as RunMode, config));
  const again = rescore(dir, scenarioId, scenario, obj.mode as RunMode);
  return {
    report,
    crossCheck,
    // only evidence with a pin had one to compare
    ...(typeof fingerprint !== "string" && report.pins.length > 0 ? { noServerKey: true as const } : {}),
    ...(again !== undefined ? { outcome: { stored: outcome, ...again } } : {}),
  };
}

/** A JSON object read from a file in the run folder, or undefined when it can't be read or is not one. */
function readObject(path: string): Record<string, unknown> | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    return typeof raw === "object" && raw !== null && !Array.isArray(raw) ? (raw as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Where the mode demo-run.json records disagrees with the runner's own files: run.json's mode, and the mode
 * config.json starts Paztport in (enforce for the modes with Paztport on, off for the others). The runner writes
 * both before pi starts, so a file that can't be read can't show the mode either.
 */
function modeDisagreements(dir: string, mode: RunMode, config: Record<string, unknown> | undefined): string[] {
  const problems: string[] = [];
  const unread = (f: string) => `${f} can't be read, so the mode demo-run.json records can't be checked against it`;
  const run = readObject(join(dir, "run.json"));
  if (run === undefined) problems.push(unread("run.json"));
  else if (run.mode !== mode) problems.push(`demo-run.json records mode ${mode}, but run.json records mode ${String(run.mode)}`);
  const serverMode = EXPECT_EVIDENCE.includes(mode) ? "enforce" : "off";
  if (config === undefined) problems.push(unread("config.json"));
  else if (config.mode !== serverMode) problems.push(`demo-run.json records mode ${mode}, but config.json starts Paztport in mode ${String(config.mode)}`);
  return problems;
}
