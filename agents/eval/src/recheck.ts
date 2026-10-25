// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { checkRun, hasEvidenceFile, reusedLocalSignatures, withProblems } from "./crosscheck.ts";
import { usableRecords, type StoredRun } from "./eval.ts";
import { DEFINITIONS, MODE_LABEL } from "./report.ts";
import type { RunMode, RunResult } from "./runner.ts";
import type { Scenario } from "../../mock-github-mcp/src/scenario.ts";
import { readLocalFacts, scoreRunFile, summarize, type Count, type ModeSummary } from "./score.ts";
import { NOT_FAILURES, verifyResultsDir } from "./verify.ts";

/**
 * A results folder checked again from its files, as they are now: every listed run re-scored from its
 * outcome log and transcript, its evidence verified and cross-checked against the outcome log and the
 * server key results.json names, and the counts recomputed. Nothing here trusts results.json's own
 * figures; they are only compared with what the files say.
 */
export type Recheck = {
  /** The listed runs, with outcome, flags, reason and evidence check as the files give them now. */
  runs: StoredRun[];
  summary: ModeSummary[];
  verify: { ok: number; failed: number; none: number; notRecorded: number };
  /** Problems that make the folder's check fail: evidence `npm run verify` fails that no run's check shows, or a key that can't be compared. */
  problems: string[];
  /** Where results.json and the files disagree, each as "results.json says X; the files say Y". */
  disagreements: string[];
  /** Things worth knowing that are not failures, such as a run whose run.json is missing. */
  notes: string[];
};

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const MODES: readonly RunMode[] = ["off", "on", "clean-off", "clean-on", "warning"];
const STATUSES: readonly RunResult["status"][] = ["completed", "timeout", "error"];
const CHECK_WORD: Record<string, string> = { ok: "verified", failed: "did not verify", none: "nothing to check", "not-recorded": "nothing recorded to check" };
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function readRunJson(runDir: string): Obj | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(runDir, "run.json"), "utf8"));
    return isObj(raw) ? raw : undefined;
  } catch {
    return undefined;
  }
}

/** The run's canary as the runner wrote it ("" when the file can't be read, which leaves only the scenario's markers). */
function readCanary(runDir: string): string {
  try {
    return readFileSync(join(runDir, "canary.txt"), "utf8").trim();
  } catch {
    return "";
  }
}

/** Compares results.json's stored counts with the recomputed ones, mode by mode and column by column. */
function compareSummaries(stored: unknown, now: ModeSummary[], out: string[]): void {
  const storedRows = new Map<string, Obj>();
  if (Array.isArray(stored)) for (const s of stored) if (isObj(s) && typeof s.mode === "string") storedRows.set(s.mode, s);
  const modes = [...new Set([...now.map((s) => s.mode as string), ...storedRows.keys()])];
  for (const mode of modes) {
    const label = MODE_LABEL[mode as RunMode] ?? mode;
    const a = storedRows.get(mode);
    const b = now.find((s) => s.mode === mode);
    if (a === undefined) {
      out.push(`results.json has no "${label}" row; the files have ${plural(b!.n, "run")} in that mode`);
      continue;
    }
    if (b === undefined) {
      out.push(`results.json has a "${label}" row; the files have no run in that mode`);
      continue;
    }
    if (a.n !== b.n) out.push(`results.json says "${label}" has ${String(a.n)} runs; the files say ${b.n}`);
    for (const d of DEFINITIONS) {
      // a column an older folder does not have, or that this table has no longer, is not a disagreement; the page
      // shows the recomputed one
      if (!(d.key in a) || !(d.key in b)) continue;
      const k = isObj(a[d.key]) ? (a[d.key] as Obj).k : undefined;
      const want = (b[d.key] as Count).k;
      if (k !== want) out.push(`results.json says ${String(k ?? "nothing")} of ${String(a.n)} "${label}" runs were ${d.term}; the files say ${want} of ${b.n}`);
    }
  }
}

/**
 * Checks a results folder again from its files. `results` is its parsed results.json (an object with a runs
 * list). `scenario` is the scenario the folder was run with; when it has local tools, each run's workspace and
 * events log are read again for local leaks, blocks and scope refusals. Without it (or for an older folder
 * whose results.json does not name that scenario) runs are scored as before, from the outcome log and transcript.
 */
export function recheckResultsDir(dir: string, results: Obj, scenario?: Scenario): Recheck {
  const localScenario = scenario?.localTools === true && isObj(results.scenario) && results.scenario.id === scenario.id ? scenario : undefined;
  const problems: string[] = [];
  const disagreements: string[] = [];
  const notes: string[] = [];
  const pin = isObj(results.serverKey) && typeof results.serverKey.fingerprint === "string" ? results.serverKey.fingerprint : undefined;
  if (pin === undefined) problems.push("results.json records no server key fingerprint, so the evidence pins can't be compared with it");
  const reports = new Map(verifyResultsDir(dir).map((r) => [r.file, r]));
  let onDisk: string[] = [];
  try {
    onDisk = readdirSync(join(dir, "runs"), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => `runs/${e.name}`);
  } catch {
    // no runs folder: every listed run is reported as missing below
  }
  // a signed local step copied from one run into another fails both
  const reused = reusedLocalSignatures(new Map(onDisk.map((rel) => [rel, join(dir, rel, "evidence.jsonl")])));
  const listed = new Set<string>();
  const runs: StoredRun[] = [];

  for (const [i, raw] of (Array.isArray(results.runs) ? results.runs : []).entries()) {
    const m = isObj(raw) && typeof raw.dir === "string" ? /^runs\/([^/]+)$/.exec(raw.dir) : null;
    if (!isObj(raw) || !m || m[1] === "." || m[1] === ".." || !MODES.includes(raw.mode as RunMode)) {
      disagreements.push(`results.json lists run ${i + 1} with a folder or mode that can't be used, so it was not checked`);
      continue;
    }
    const rel = raw.dir as string;
    const name = m[1]!;
    const mode = raw.mode as RunMode;
    if (listed.has(rel)) {
      disagreements.push(`results.json lists ${name} twice; the folder has it once`);
      continue;
    }
    listed.add(rel);
    const runDir = join(dir, rel);
    const storedStatus = STATUSES.includes(raw.status as RunResult["status"]) ? (raw.status as RunResult["status"]) : "error";
    let result: RunResult;
    const rj = readRunJson(runDir);
    if (rj !== undefined && STATUSES.includes(rj.status as RunResult["status"])) {
      result = { status: rj.status as RunResult["status"], exitCode: typeof rj.exitCode === "number" ? rj.exitCode : null, durationMs: 0, canary: "", mode };
      if (rj.mode !== undefined && rj.mode !== mode) disagreements.push(`results.json says ${name} ran with mode ${mode}; its run.json says ${String(rj.mode)}`);
    } else {
      result = { status: storedStatus, exitCode: null, durationMs: 0, canary: "", mode };
      if (existsSync(runDir)) notes.push(`${name}: run.json can't be read, so the status results.json records (${storedStatus}) was used`);
    }
    const index = typeof raw.index === "number" ? raw.index : i + 1;
    let run: StoredRun;
    if (!existsSync(runDir)) {
      run = { mode, index, dir: rel, outcome: "error", readPrivate: false, taskDone: false, ...(localScenario !== undefined ? { scopeRefused: false } : {}), harnessFault: false, status: result.status, reason: "its folder isn't there" };
    } else {
      const local = localScenario === undefined ? undefined : readLocalFacts(runDir, localScenario, readCanary(runDir), mode);
      run = scoreRunFile(join(runDir, "outcome.jsonl"), result, index, rel, join(runDir, "transcript.jsonl"), local);
      if (run.outcome === "error" && run.reason === undefined) {
        run.reason =
          raw.outcome === "error" && typeof raw.reason === "string"
            ? raw.reason
            : result.exitCode === null
              ? "pi did not run to completion (see stderr.txt)"
              : `pi exited with code ${result.exitCode} (see stderr.txt)`;
      }
    }
    const evidencePath = join(runDir, "evidence.jsonl");
    run.evidenceFile = hasEvidenceFile(evidencePath);
    const file = `${rel}/evidence.jsonl`;
    run.verify = checkRun({
      mode,
      outcome: run.outcome,
      records: usableRecords(join(runDir, "outcome.jsonl")),
      evidencePath,
      eventsPath: join(runDir, "events.jsonl"),
      report: run.evidenceFile ? reports.get(file) : undefined,
      expectedPin: pin ?? "",
      // results.json can be edited: the scenario the folder is checked with also says whether it has local tools
      localTools: results.localTools === true || localScenario !== undefined,
    });
    // what `npm run verify` fails on its own (an unreadable outcome log, for example) is a failure here too
    const vr = reports.get(file);
    if (vr !== undefined && !vr.ok && run.verify.status !== "failed") {
      const why = vr.problem ?? vr.items.find((x) => !NOT_FAILURES.includes(x.result))?.result ?? "it does not verify";
      run.verify = { status: "failed", problems: [`npm run verify fails ${file}: ${why}`] };
    }
    run.verify = withProblems(run.verify, reused.get(rel));
    runs.push(run);

    if (raw.outcome !== run.outcome) disagreements.push(`results.json says ${name} was ${String(raw.outcome ?? "not scored")}; the files say ${run.outcome}`);
    const storedCheck = isObj(raw.verify) ? raw.verify.status : undefined;
    if (storedCheck !== undefined && storedCheck !== run.verify.status) {
      disagreements.push(`results.json says ${name}'s evidence check was "${CHECK_WORD[String(storedCheck)] ?? String(storedCheck)}"; the files say "${CHECK_WORD[run.verify.status]}"`);
    }
  }

  // a run folder results.json leaves out is a run that the table does not count
  for (const rel of onDisk.sort()) if (!listed.has(rel)) disagreements.push(`the folder has ${rel.slice(5)}, which results.json does not list or count`);
  for (const r of reports.values()) {
    const owner = r.file.replace(/\/evidence\.jsonl$/, "");
    if (!r.ok && !listed.has(owner)) problems.push(`npm run verify fails ${r.file}: ${r.problem ?? r.items.find((x) => !NOT_FAILURES.includes(x.result))?.result ?? "it does not verify"}`);
  }

  const summary = summarize(runs, results.localTools === true || localScenario !== undefined);
  const verify = { ok: 0, failed: 0, none: 0, notRecorded: 0 };
  for (const r of runs) {
    const st = r.verify!.status;
    if (st === "ok") verify.ok++;
    else if (st === "failed") verify.failed++;
    else if (st === "none") verify.none++;
    else verify.notRecorded++;
  }
  compareSummaries(results.summary, summary, disagreements);
  const storedVerify = isObj(results.verify) ? results.verify : {};
  const words: [keyof typeof verify, string][] = [["ok", "verified"], ["failed", "did not verify"], ["none", "had nothing to check"], ["notRecorded", "recorded nothing to check"]];
  for (const [k, word] of words) {
    if (storedVerify[k] !== undefined && storedVerify[k] !== verify[k]) disagreements.push(`results.json says ${String(storedVerify[k])} runs ${word}; the files say ${verify[k]}`);
  }
  return { runs, summary, verify, problems, disagreements, notes };
}

/** A cheap fingerprint of the files a recheck reads, so a result can be reused until one of them changes. */
export function recheckSignature(dir: string, publicFolders: readonly string[] = []): string {
  const parts: string[] = [];
  const stamp = (p: string) => {
    try {
      const st = statSync(p);
      parts.push(`${p}:${st.size}:${st.mtimeMs}`);
    } catch {
      parts.push(`${p}:-`);
    }
  };
  stamp(join(dir, "results.json"));
  let names: string[] = [];
  try {
    names = readdirSync(join(dir, "runs")).sort();
  } catch {
    // none
  }
  // every file and folder under the scenario's public folders, by mtime and size; bounded, links not followed
  let budget = 5000;
  const walk = (base: string, rel: string): void => {
    if (budget-- <= 0) return;
    const at = join(base, rel);
    let st;
    try {
      st = lstatSync(at);
    } catch {
      parts.push(`${at}:-`);
      return;
    }
    parts.push(`${at}:${st.size}:${st.mtimeMs}`);
    if (!st.isDirectory()) return;
    let kids: string[] = [];
    try {
      kids = readdirSync(at).sort();
    } catch {
      return;
    }
    for (const k of kids) walk(base, join(rel, k));
  };
  for (const n of names) for (const f of publicFolders) walk(join(dir, "runs", n, "workspace"), f);
  for (const n of names) for (const f of ["outcome.jsonl", "evidence.jsonl", "transcript.jsonl", "run.json", "events.jsonl", "canary.txt", "workspace"]) stamp(join(dir, "runs", n, f));
  return parts.join("|");
}
