// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { collectEnvironment, type Environment } from "./environment.ts";
import { checkRun, hasEvidenceFile, type RunVerify } from "./crosscheck.ts";
import { checkModelAvailable, parseModel, prepareAgentDir, runOnce, type ModelRef, type RunMode, type RunResult, type RunSpec } from "./runner.ts";
import { redactPaths, withRealPath } from "./redact.ts";
import { renderSummary } from "./report.ts";
import { checkRecords, readOutcomeLog, scoreRunFile, summarize, type ModeSummary, type ScoredRun } from "./score.ts";
import { pinFingerprint, verifyEvidence, verifyResultsDir, type VerifyReport } from "./verify.ts";

export type EvalOptions = {
  model: string;
  runs: number;
  modes: RunMode[];
  scenarioDir: string;
  payloadFile?: string;
  agentDir?: string;
  outDir: string;
  timeoutMs: number;
  command: string;
};
/** A scored run as stored in results.json: the score, why it is an error if the cause is not its status, and the evidence check. */
export type StoredRun = ScoredRun & {
  verify?: RunVerify;
  /** evidence.jsonl exists and holds more than the unsigned run record (see hasEvidenceFile). */
  evidenceFile?: boolean;
};
export type ResultsFile = {
  formatVersion: 1;
  incomplete: boolean;
  date: string;
  /** The command as typed, with paths under agents/ written relative to it ("./...") and the home folder as `<home>`. */
  command: string;
  /**
   * With --agent-dir: which of the files pi applies to every run (SYSTEM.md, APPEND_SYSTEM.md, settings.json)
   * that folder holds, by name only. Absent without --agent-dir, and in folders written before it was recorded.
   */
  agentDirFiles?: string[];
  scenario: { id: string; title: string };
  payload: { kind: "reference" | "custom"; sha256: string };
  model: ModelRef;
  versions: { pi: string; extension: string; mockServer: string; node: string };
  /** The machine and, for an ollama model, Ollama's version and the model's digest. Absent in folders written before it was recorded. */
  environment?: Environment;
  tools: string;
  warning?: { source: string; url: string; retrieved: string; placement: string; note?: string };
  runs: StoredRun[];
  summary: ModeSummary[];
  /**
   * Runs by evidence check: verified, not verified, with nothing to check (Paztport off), and with
   * Paztport on but ended in error before anything was recorded.
   */
  verify: { ok: number; failed: number; none: number; notRecorded: number };
  /** Fingerprint of this eval's server policy public key: every evidence file must show it as its pin. */
  serverKey: { fingerprint: string };
  /** What was asked for, so a table shows every requested mode and an unfinished eval says how far it got. */
  requested: { modes: RunMode[]; runs: number };
};
export type EvalDeps = {
  runOnce?: typeof runOnce;
  checkModel?: typeof checkModelAvailable;
  /** Used to ask Ollama for its version and the model's digest. */
  fetch?: typeof fetch;
  signal?: AbortSignal;
  log?: (s: string) => void;
};

const AGENTS = resolve(import.meta.dirname, "../..");
/** Files in a pi agent folder that change every run: the system prompt, an addition to it, and settings. */
const AGENT_DIR_FILES = ["SYSTEM.md", "APPEND_SYSTEM.md", "settings.json"];

/** The command for results.json: no user name or folder layout from absolute paths. */
export function commandForResults(command: string): string {
  return redactPaths(command, [...withRealPath({ path: AGENTS, placeholder: "." }), ...withRealPath({ path: homedir(), placeholder: "<home>" })]);
}
const SETUP_DEMO = join(AGENTS, "scripts/setup-demo.ts");
const BASELINES = join(import.meta.dirname, "../baselines");
const ALL_MODES: readonly RunMode[] = ["off", "on", "clean-off", "clean-on", "warning"];

function packageVersion(...parts: string[]): string {
  try {
    const v: unknown = (JSON.parse(readFileSync(join(AGENTS, ...parts, "package.json"), "utf8")) as { version?: unknown }).version;
    return typeof v === "string" && v !== "" ? v : "unknown";
  } catch {
    return "unknown";
  }
}

function sha256File(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** Writes through a temporary file, so a reader never sees half a file. */
function writeAtomic(file: string, text: string): void {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, text);
  renameSync(tmp, file);
}

function readWarning(): NonNullable<ResultsFile["warning"]> {
  const raw: unknown = JSON.parse(readFileSync(join(BASELINES, "warning.json"), "utf8"));
  const o = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  for (const k of ["source", "url", "retrieved", "placement"]) {
    if (typeof o[k] !== "string" || o[k] === "") throw new Error(`baselines/warning.json: ${k} must be a non-empty string`);
  }
  if (!existsSync(join(BASELINES, "warning.md"))) throw new Error("baselines/warning.md is missing");
  return {
    source: o.source as string,
    url: o.url as string,
    retrieved: o.retrieved as string,
    placement: o.placement as string,
    ...(typeof o.note === "string" && o.note !== "" ? { note: o.note } : {}),
  };
}

function validate(o: EvalOptions): void {
  if (!Number.isInteger(o.runs) || o.runs < 1) throw new Error("runs must be a whole number of at least 1");
  if (!Array.isArray(o.modes) || o.modes.length === 0) throw new Error("modes must name at least one mode");
  for (const m of o.modes) if (!ALL_MODES.includes(m)) throw new Error(`unknown mode "${String(m)}" (modes: ${ALL_MODES.join(", ")})`);
  if (new Set(o.modes).size !== o.modes.length) throw new Error("modes must not repeat");
  if (typeof o.timeoutMs !== "number" || !Number.isFinite(o.timeoutMs) || o.timeoutMs <= 0) throw new Error("timeout must be a positive number of seconds");
  if (o.payloadFile !== undefined && !existsSync(o.payloadFile)) throw new Error(`payload file not found: ${o.payloadFile}`);
}

/** The records of a log that can be scored, or null when it cannot be read or used. */
function usableRecords(file: string): OutcomeRecord[] | null {
  try {
    const records = readOutcomeLog(file);
    return checkRecords(records) === undefined ? records : null;
  } catch {
    return null;
  }
}

/** The folder that holds an eval's keys: next to the results folder, never inside it. */
export function keysDirFor(outDir: string): string {
  const out = resolve(outDir);
  return join(out, "..", `.keys-${basename(out)}`);
}

function makeKeys(dir: string): string {
  if (existsSync(dir)) throw new Error(`${dir} already exists; remove it (it holds keys from an earlier eval) and run again`);
  const r = spawnSync(process.execPath, [SETUP_DEMO, "--out", dir], { encoding: "utf8" });
  if (r.status !== 0) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`could not create demo keys: ${(r.stderr || r.stdout || "setup-demo failed").trim()}`);
  }
  // the server policy public key the client pins; its fingerprint is what every evidence file must show
  return pinFingerprint(readFileSync(join(dir, "client/server-policy.pub"), "utf8").trim());
}

/**
 * Runs `runs` stock-pi runs for each mode, interleaved round-robin, and writes a results folder:
 * results.json, summary.md and runs/<mode>-<nnn>/. Both files are rewritten after every run, so a crash
 * leaves a valid folder. An abort ends the current run, writes the folder as incomplete and returns.
 * Fresh keys are made for the eval in a sibling folder `.keys-<name>`, outside the results, and removed at the end.
 */
export async function runEval(opts: EvalOptions, deps: EvalDeps = {}): Promise<ResultsFile> {
  const run = deps.runOnce ?? runOnce;
  const log = deps.log ?? (() => {});
  validate(opts);
  const out = resolve(opts.outDir);
  const name = basename(out);
  const model = parseModel(opts.model);
  const scenario = loadScenario(opts.scenarioDir);
  const wantsWarning = opts.modes.includes("warning");
  const warning = wantsWarning ? readWarning() : undefined;
  const userAgentDir = opts.agentDir !== undefined;
  const agentDir = resolve(opts.agentDir ?? join(out, "..", `.agent-${name}`));

  if (existsSync(out) && readdirSync(out).length > 0) throw new Error(`${out} already has files; choose an empty or new --out`);
  // a missing Ollama or model is one plain message, before anything is created
  await (deps.checkModel ?? checkModelAvailable)(model);
  prepareAgentDir(agentDir, model, userAgentDir);
  const agentDirFiles = userAgentDir ? AGENT_DIR_FILES.filter((f) => existsSync(join(agentDir, f))) : undefined;
  if (agentDirFiles !== undefined && agentDirFiles.length > 0) {
    log(`Your pi agent folder has ${agentDirFiles.join(", ")}; pi applies them to every run, and results.json names them.`);
  }

  const keysDir = keysDirFor(out);
  mkdirSync(join(out, ".."), { recursive: true });
  const expectedPin = makeKeys(keysDir);
  const evidenceOf = (dir: string) => join(out, dir, "evidence.jsonl");
  mkdirSync(out, { recursive: true });

  try {
    mkdirSync(join(out, "runs"), { recursive: true });
    if (warning !== undefined) {
      copyFileSync(join(BASELINES, "warning.md"), join(out, "warning.md"));
      copyFileSync(join(BASELINES, "warning.json"), join(out, "warning.json"));
    }
    const payloadFile = opts.payloadFile ?? scenario.payloadFile;
    const results: ResultsFile = {
      formatVersion: 1,
      incomplete: true,
      date: new Date().toISOString(),
      command: commandForResults(opts.command),
      ...(agentDirFiles !== undefined ? { agentDirFiles } : {}),
      scenario: { id: scenario.id, title: scenario.title },
      payload: { kind: opts.payloadFile === undefined ? "reference" : "custom", sha256: sha256File(payloadFile) },
      model,
      versions: {
        pi: packageVersion("node_modules", "@earendil-works", "pi-coding-agent"),
        extension: packageVersion("pi-extension"),
        mockServer: packageVersion("mock-github-mcp"),
        node: process.version,
      },
      environment: await collectEnvironment(model, deps.fetch),
      tools: scenario.tools,
      ...(warning !== undefined ? { warning } : {}),
      runs: [],
      summary: [],
      verify: { ok: 0, failed: 0, none: 0, notRecorded: 0 },
      serverKey: { fingerprint: expectedPin },
      requested: { modes: [...opts.modes], runs: opts.runs },
    };
    const planned = opts.runs * opts.modes.length;
    const records = new Map<string, OutcomeRecord[] | null>();

    const assess = (r: StoredRun, report: VerifyReport | undefined): RunVerify =>
      checkRun({ mode: r.mode, outcome: r.outcome, records: records.get(r.dir) ?? null, evidencePath: join(out, r.dir, "evidence.jsonl"), report, expectedPin });
    const tally = () => {
      const t = { ok: 0, failed: 0, none: 0, notRecorded: 0 };
      for (const r of results.runs) {
        const st = r.verify?.status;
        if (st === "ok") t.ok++;
        else if (st === "failed") t.failed++;
        else if (st === "none") t.none++;
        else if (st === "not-recorded") t.notRecorded++;
      }
      return t;
    };
    const write = () => {
      results.summary = summarize(results.runs);
      results.verify = tally();
      // a run that was interrupted is recorded, but the eval is still not finished, even if it was the last one
      results.incomplete = results.runs.length < planned || deps.signal?.aborted === true;
      writeAtomic(join(out, "results.json"), JSON.stringify(results, null, 2) + "\n");
      writeAtomic(join(out, "summary.md"), renderSummary(results));
    };

    write();

    outer: for (let index = 1; index <= opts.runs; index++) {
      for (const mode of opts.modes) {
        if (deps.signal?.aborted) break outer;
        const dir = `runs/${mode}-${String(index).padStart(3, "0")}`;
        const runDir = join(out, dir);
        mkdirSync(runDir, { recursive: true });
        const spec: RunSpec = {
          scenarioDir: resolve(opts.scenarioDir),
          mode,
          model,
          runDir,
          demoDir: keysDir,
          agentDir,
          userAgentDir,
          timeoutMs: opts.timeoutMs,
          ...(opts.payloadFile !== undefined ? { payloadFile: resolve(opts.payloadFile) } : {}),
          ...(mode === "warning" ? { warning: { file: join(out, "warning.md") } } : {}),
        };
        let result: RunResult;
        let thrown: string | undefined;
        try {
          result = await run(spec, undefined, deps.signal);
        } catch (e) {
          thrown = `the run could not be started: ${(e as Error).message}`;
          result = { status: "error", exitCode: null, durationMs: 0, canary: "", mode };
        }
        const logFile = join(runDir, "outcome.jsonl");
        const scored: StoredRun = scoreRunFile(logFile, result, index, dir, join(runDir, "transcript.jsonl"));
        if (scored.outcome === "error" && scored.reason === undefined) {
          scored.reason =
            thrown ??
            (deps.signal?.aborted && result.status === "error"
              ? "the eval was interrupted before this run finished"
              : result.exitCode === null
                ? "pi did not run to completion (see stderr.txt)"
                : `pi exited with code ${result.exitCode} (see stderr.txt)`);
        }
        records.set(dir, usableRecords(logFile));
        const evidencePath = evidenceOf(dir);
        scored.evidenceFile = hasEvidenceFile(evidencePath);
        scored.verify = assess(scored, scored.evidenceFile ? verifyEvidence(evidencePath) : undefined);
        results.runs.push(scored);
        write();
        log(`[${results.runs.length}/${planned}] ${basename(dir)}: ${scored.outcome} (${scored.status}, ${Math.round(result.durationMs / 1000)}s)${scored.reason !== undefined ? ` - ${scored.reason}` : ""}`);
      }
    }

    // The whole folder is checked once more at the end, from the files as they are now:
    // evidence by verifyResultsDir, and each outcome log read again from disk.
    if (results.runs.length > 0) {
      const reports = new Map(verifyResultsDir(out).map((r) => [r.file, r]));
      for (const r of results.runs) {
        const file = `${r.dir}/evidence.jsonl`;
        records.set(r.dir, usableRecords(join(out, r.dir, "outcome.jsonl")));
        r.evidenceFile = hasEvidenceFile(evidenceOf(r.dir));
        r.verify = assess(r, r.evidenceFile ? reports.get(file) : undefined);
      }
    }
    write();
    return results;
  } finally {
    rmSync(keysDir, { recursive: true, force: true });
  }
}
