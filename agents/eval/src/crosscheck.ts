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
 * unsigned run record: Paztport off, or on and ended before a session). The eval, the page and the CLI all
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
 */
export function checkRun(input: {
  mode: RunMode;
  /** The scored outcome. A run scored "error" or "timeout" with Paztport on and nothing recorded is not held against its missing evidence. */
  outcome: string;
  records: OutcomeRecord[] | null;
  evidencePath: string;
  report: VerifyReport | undefined;
  expectedPin: string;
}): RunVerify {
  const { mode, outcome, records, report, expectedPin } = input;
  const problems: string[] = [];
  const attested = records?.some((r) => typeof r.sess === "string") ?? false;

  if (report === undefined || report.nothingToCheck === true) {
    if (attested) problems.push("the outcome log shows attested calls, but evidence.jsonl is missing, empty or has no signed records");
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

  const capped = problems.length > MAX_PROBLEMS ? [...problems.slice(0, MAX_PROBLEMS), `and ${problems.length - MAX_PROBLEMS} more`] : problems;
  return { status: problems.length > 0 ? "failed" : "ok", problems: capped };
}
