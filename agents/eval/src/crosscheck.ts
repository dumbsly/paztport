// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, statSync } from "node:fs";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { NOT_FAILURES, verifyEvidence, type VerifyReport } from "./verify.ts";
import type { RunMode } from "./runner.ts";

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

/** True when a local event was made during a run: the gate signs those (in enforce mode), and only those. */
const inRun = (e: LocalEvent): boolean => typeof e.rid === "string";

type LocalRecord = { tool: string; verdict: string };
/** The tool and verdict of each local record of an evidence file, by line number (the same numbering `verify` reports). */
function localsByLine(path: string): Map<number, LocalRecord> {
  const out = new Map<number, LocalRecord>();
  readFileSync(path, "utf8")
    .split("\n")
    .forEach((raw, i) => {
      try {
        const r: unknown = JSON.parse(raw);
        if (typeof r === "object" && r !== null) {
          const o = r as Record<string, unknown>;
          if (o.type === "local" && typeof o.tool === "string" && typeof o.verdict === "string") out.set(i + 1, { tool: o.tool, verdict: o.verdict });
        }
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
 * same call id and verdict, and every verified local record must have its event, so a local block counts only
 * when its signed refusal verified. A local event outside a run is unsigned by design, and the gate refuses
 * every call there as out of scope, so it must be SCOPE_DENIED. A run with Paztport on is in enforce mode, which
 * writes the client record before any local call, so local events made during a run need one. A call that the
 * gate allowed and something later stopped (another handler, an abort) has an OK record and an OK event; that
 * is not a disagreement.
 */
function crossCheckLocal(events: LocalEvent[], report: VerifyReport, evidencePath: string): string[] {
  const problems: string[] = [];
  const ids = idsByLine(evidencePath);
  const locals = localsByLine(evidencePath);
  const hasClient = report.items.some((i) => i.type === "client");
  const verified = new Map<string, LocalRecord & { callId: string }>();
  for (const item of report.items) {
    const id = ids.get(item.line);
    const rec = locals.get(item.line);
    if (item.type === "local" && (item.result === "OK" || item.result === "REFUSED") && id !== undefined && rec !== undefined) {
      verified.set(key(id), { ...rec, callId: id.callId });
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
 * @param expectedPin the fingerprint of this eval's server policy public key
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
  expectedPin: string;
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
    if (p !== expectedPin) problems.push(`evidence.jsonl is pinned to server key ${p}, not this eval's server key ${expectedPin}`);
  }
  if (report.pins.length === 0 && (attested || EXPECT_EVIDENCE.includes(mode))) problems.push("evidence.jsonl has no verified session");
  if (records === null) problems.push("the outcome log could not be used, so the evidence could not be compared with it");
  else problems.push(...crossCheck(records, report, input.evidencePath));
  if (eventsProblem !== undefined) problems.push(`${eventsProblem}, so its local tool calls could not be compared with evidence.jsonl`);
  else problems.push(...crossCheckLocal(events as LocalEvent[], report, input.evidencePath));

  const capped = problems.length > MAX_PROBLEMS ? [...problems.slice(0, MAX_PROBLEMS), `and ${problems.length - MAX_PROBLEMS} more`] : problems;
  return { status: problems.length > 0 ? "failed" : "ok", problems: capped };
}
