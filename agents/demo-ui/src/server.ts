// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import { hasEvidenceFile } from "../../eval/src/crosscheck.ts";
import { runEval, type EvalOptions, type ResultsFile } from "../../eval/src/eval.ts";
import { checkModelAvailable, parseModel, runOnce, type LineFile, type ModelRef, type RunMode, type RunResult, type RunSpec } from "../../eval/src/runner.ts";
import { recheckResultsDir, recheckSignature, type Recheck } from "../../eval/src/recheck.ts";
import { DEFINITIONS, LIMITS, MODE_LABEL } from "../../eval/src/report.ts";
import { scoreRunFile, type ScoredRun } from "../../eval/src/score.ts";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { loadScenario, type Scenario } from "../../mock-github-mcp/src/scenario.ts";
import { buildSteps, finalAnswer, PLAIN_CLASS, type Step } from "./steps.ts";

export type DemoServerOptions = {
  /** Where single runs and evals are written, and where the results browser looks. */
  resultsRoot: string;
  /** Holds client/ and server/ keys for single runs. Never inside resultsRoot. */
  demoDir: string;
  /** A scenario folder (it holds scenario.json), or a folder of scenario folders. */
  scenarioDir: string;
  /** The per-launch key every /api request must carry in x-demo-key. */
  key: string;
  /** The user's own pi agent dir (the opt-in for hosted providers). Without it every run is isolated and local. */
  userAgentDir?: string;
  /** Published results folders to list beside the ones under resultsRoot. */
  extraResults?: string[];
  /** Per-run time limit. Default 600 s. */
  timeoutMs?: number;
  deps?: { runOnce?: typeof runOnce; runEval?: typeof runEval; fetch?: typeof fetch };
};
export type DemoServer = { url: string; close(): Promise<void> };

type Settings = { model: string; scenario: string; mode: "on" | "off"; runs: number; payload?: string };
type Payload = { kind: "reference" | "custom"; sha256: string };
type Logs = { transcript: unknown[]; events: unknown[]; outcome: OutcomeRecord[]; evidence: unknown[] };
type Sent = { event: string; data: unknown };
type Obj = Record<string, unknown>;

const PUBLIC_DIR = join(import.meta.dirname, "../public");
/** `npm run verify` runs from here, so the commands the page shows are relative to it when they can be. */
const AGENTS_DIR = resolve(import.meta.dirname, "../..");
const OLLAMA_TAGS = "http://127.0.0.1:11434/api/tags";
const DEFAULT_TIMEOUT_MS = 600_000;
const MAX_RUNS = 100;
const MAX_BODY = 256 * 1024;
const MAX_PAYLOAD = 64 * 1024;
const KEEP_RUNS = 20;
const HEARTBEAT_MS = 15_000;
const PROGRESS_POLL_MS = 1000;

export const REFUSALS_NOTE = "Refusals are unsigned. Each one is checked for its shape and against the server's own log.";
const TOOLS_NOTE = "In these runs the agent gets only the scenario's mock repository tools. It has no shell and no file tools.";
const HOSTED_NOTE = "A hosted model receives this run's prompts and tool results under that provider's terms. Read them before you start.";
const MISTRAL_NOTE = "Mistral's hosted API is not permitted for this demo.";
const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
};

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const pad = (n: number) => String(n).padStart(2, "0");
const stamp = (d: Date) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;

/** Lines of a JSONL file that parse; a missing file or a bad line is skipped, never thrown. */
function readJsonl(file: string): unknown[] {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const out: unknown[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      // a half-written line
    }
  }
  return out;
}

/** The command that checks a run's evidence, as typed in agents/. */
function verifyCommand(target: string): string {
  const rel = relative(AGENTS_DIR, target);
  const shown = rel !== "" && !rel.startsWith("..") && !rel.split(sep).includes("..") ? rel : target;
  return `npm run verify -- ${/^[A-Za-z0-9_./:@%+=,-]+$/.test(shown) ? shown : `'${shown.replace(/'/g, "'\\''")}'`}`;
}

/**
 * The run's evidence file and the command that checks it, when it holds something signed to check. A file
 * with only the unsigned run record (an older Paztport-off run, or one that ended before a session) does not.
 */
function evidenceOf(runDir: string): { evidenceFile: boolean; verifyCommand?: string } {
  const file = join(runDir, "evidence.jsonl");
  return hasEvidenceFile(file) ? { evidenceFile: true, verifyCommand: verifyCommand(file) } : { evidenceFile: false };
}

/** The folder's verify command, only when its runs have something that was, or should have been, checked. */
function folderVerify(dir: string, status: VerifyStatus): { verifyCommand?: string } {
  return status === "verified" || status === "partly-checked" || status === "failed" ? { verifyCommand: verifyCommand(dir) } : {};
}

const median = (xs: number[]): number | undefined => {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid]! : Math.round((s[mid - 1]! + s[mid]!) / 2);
};
/** How long a completed run took; a run that timed out, failed or was cancelled says nothing about that. */
const durationOf = (v: unknown): number | undefined =>
  isObj(v) && v.status === "completed" && typeof v.durationMs === "number" && Number.isFinite(v.durationMs) && v.durationMs >= 0 ? v.durationMs : undefined;

/** A JSON file, or undefined when it is missing or unreadable. */
function readJson(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
}

function logsFromDir(dir: string): Logs {
  return {
    transcript: readJsonl(join(dir, "transcript.jsonl")),
    events: readJsonl(join(dir, "events.jsonl")),
    outcome: readJsonl(join(dir, "outcome.jsonl")).filter(isObj) as unknown as OutcomeRecord[],
    evidence: readJsonl(join(dir, "evidence.jsonl")),
  };
}

type ScenarioEntry = { id: string; dir: string; scenario: Scenario };
/** `dir` is one scenario folder, or a folder of them. A folder that does not load is left out. */
function listScenarios(dir: string): ScenarioEntry[] {
  const load = (d: string): ScenarioEntry[] => {
    try {
      const scenario = loadScenario(d);
      return [{ id: scenario.id, dir: d, scenario }];
    } catch {
      return [];
    }
  };
  if (existsSync(join(dir, "scenario.json"))) return load(dir);
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort()
      .flatMap((name) => load(join(dir, name)));
  } catch {
    return [];
  }
}

function keyMatches(given: string | string[] | undefined, key: string): boolean {
  if (typeof given !== "string") return false;
  // equal-length digests, so the comparison takes the same time whatever the guess
  return timingSafeEqual(createHash("sha256").update(given).digest(), createHash("sha256").update(key).digest());
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "That request is too large.");
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "The request body isn't valid JSON.");
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(text);
}

// --- results folders -------------------------------------------------------------------------------------------

type Folder = { name: string; dir: string };
type Loaded = { ok: true; kind: "eval"; results: Obj } | { ok: true; kind: "single"; run: Obj } | { ok: false; error: string };

/** Reads a results folder without throwing: any problem comes back as { ok: false, error }. */
function loadFolder(dir: string): Loaded {
  const evalFile = join(dir, "results.json");
  const singleFile = join(dir, "demo-run.json");
  const file = existsSync(evalFile) ? evalFile : existsSync(singleFile) ? singleFile : undefined;
  if (file === undefined) return { ok: false, error: "There is no results.json in this folder." };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    return { ok: false, error: `${basename(file)} can't be read as JSON (${(e as Error).message}).` };
  }
  if (!isObj(raw)) return { ok: false, error: `${basename(file)} doesn't hold a results object.` };
  if (raw.formatVersion !== 1) return { ok: false, error: `${basename(file)} has formatVersion ${String(raw.formatVersion)}; this page reads version 1.` };
  if (file === singleFile) {
    if (!isObj(raw.result)) return { ok: false, error: "demo-run.json has no run result." };
    return { ok: true, kind: "single", run: raw };
  }
  if (!Array.isArray(raw.runs)) return { ok: false, error: "results.json has no list of runs." };
  return { ok: true, kind: "eval", results: raw };
}

type VerifyStatus = "verified" | "failed" | "partly-checked" | "nothing-to-check" | "unknown";
const runsWord = (n: number) => `${n} run${n === 1 ? "" : "s"}`;
/**
 * What the evidence checks add up to. An empty list is never "verified", and runs with Paztport on that ended
 * before anything was recorded are counted on their own ("partly checked"), never folded into "verified".
 */
function verifyOf(runs: unknown[]): { verifyStatus: VerifyStatus; verifyLine: string } {
  if (runs.length === 0) return { verifyStatus: "nothing-to-check", verifyLine: "There are no runs in this folder, so there is nothing to check." };
  const checks = runs.map((r) => (isObj(r) && isObj(r.verify) ? r.verify.status : undefined));
  const missing = checks.filter((s) => s === undefined).length;
  if (missing > 0) return { verifyStatus: "unknown", verifyLine: `${missing} of ${runs.length} runs have no evidence check recorded.` };
  const count = (st: string) => checks.filter((s) => s === st).length;
  const [ok, failed, none, notRecorded] = [count("ok"), count("failed"), count("none"), count("not-recorded")];
  if (failed > 0) return { verifyStatus: "failed", verifyLine: `${failed} of ${runs.length} runs have evidence that did not verify.` };
  if (notRecorded > 0) {
    const parts = [
      `${ok} of ${runs.length} runs have evidence that verified.`,
      `${runsWord(notRecorded)} with Paztport on ended before Paztport recorded anything, so ${notRecorded === 1 ? "it has" : "they have"} nothing to check.`,
    ];
    if (none > 0) parts.push(`${runsWord(none)} had Paztport off.`);
    return { verifyStatus: "partly-checked", verifyLine: parts.join(" ") };
  }
  if (ok === 0) return { verifyStatus: "nothing-to-check", verifyLine: "No run has evidence to check: Paztport was off." };
  const rest = none > 0 ? ` ${runsWord(none)} had Paztport off, so ${none === 1 ? "it has" : "they have"} nothing to check.` : "";
  return { verifyStatus: "verified", verifyLine: `${ok} of ${runs.length} runs have evidence that verified.${rest}` };
}

export const RECORDED_NOTE = "Recorded by the eval that wrote this folder.";
export const CHECKED_NOTE =
  "Checked now, from the files in this folder: each run re-scored from its outcome log and transcript, its evidence verified and compared with the outcome log and the server key, and the counts recomputed.";
export const DISAGREE_NOTE =
  "Where results.json and the files disagree, the table shows what the files say. A difference can mean a file was edited, or that the folder was written by an earlier version of the eval whose scoring rules differ.";

type Checked = { recheck: Recheck; verifyStatus: VerifyStatus; verifyLine: string } | { error: string };
/** The folder checked again now (see recheckResultsDir), reused until one of the files it reads changes. */
const recheckCache = new Map<string, { sig: string; value: Checked }>();
function checkNow(dir: string, results: Obj): Checked {
  const sig = recheckSignature(dir);
  const hit = recheckCache.get(dir);
  if (hit !== undefined && hit.sig === sig) return hit.value;
  let value: Checked;
  try {
    const recheck = recheckResultsDir(dir, results);
    const v = verifyOf(recheck.runs);
    // a failure verify finds outside any listed run (results.json itself, an unlisted run) fails the folder too
    value =
      recheck.problems.length > 0
        ? { recheck, verifyStatus: "failed", verifyLine: `${v.verifyLine} ${recheck.problems.length === 1 ? "One more problem" : `${recheck.problems.length} more problems`}: ${recheck.problems.join("; ")}.` }
        : { recheck, ...v };
  } catch (e) {
    value = { error: `This folder could not be checked again (${(e as Error).message}).` };
  }
  recheckCache.set(dir, { sig, value });
  return value;
}

// --- the server ------------------------------------------------------------------------------------------------

type ActiveRun = {
  id: string;
  settings: Settings;
  ac: AbortController;
  buffer: Sent[];
  clients: Set<ServerResponse>;
  finished: boolean;
  cancelled: boolean;
  /** The run got as far as producing output (a log line, or an eval's results file). */
  started: boolean;
  /** A single run's steps from what it has written so far (the files, or the lines seen when a file is missing). */
  stepsSoFar?: () => Step[];
  finishedPromise: Promise<void>;
};

export async function startDemoServer(opts: DemoServerOptions): Promise<DemoServer> {
  const doRunOnce = opts.deps?.runOnce ?? runOnce;
  const doRunEval = opts.deps?.runEval ?? runEval;
  const doFetch = opts.deps?.fetch ?? fetch;
  const resultsRoot = resolve(opts.resultsRoot);
  const demoDir = resolve(opts.demoDir);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const isolatedAgentDir = join(dirname(demoDir), "agent-ui");
  const payloadDir = join(dirname(demoDir), "payloads");
  const userAgentDir = opts.userAgentDir !== undefined ? resolve(opts.userAgentDir) : undefined;

  const runs = new Map<string, ActiveRun>();
  let active: ActiveRun | undefined;
  let port = 0;

  const folders = (): Folder[] => {
    const out: Folder[] = [];
    const seen = new Set<string>();
    const add = (name: string, dir: string) => {
      let n = name;
      for (let i = 2; seen.has(n); i++) n = `${name}-${i}`;
      seen.add(n);
      out.push({ name: n, dir });
    };
    try {
      for (const e of readdirSync(resultsRoot, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        if (e.isDirectory() && !e.name.startsWith(".")) add(e.name, join(resultsRoot, e.name));
      }
    } catch {
      // no results yet
    }
    for (const d of opts.extraResults ?? []) add(basename(resolve(d)), resolve(d));
    return out;
  };

  const scenarioFor = (id: string): Scenario => listScenarios(opts.scenarioDir).find((s) => s.id === id)?.scenario ?? ({ serverId: "github", steps: {} } as unknown as Scenario);

  // --- starting runs ---

  function parseSettings(raw: unknown): { settings: Settings; model: ModelRef; entry: ScenarioEntry } {
    if (!isObj(raw)) throw new HttpError(400, "The request needs a model, scenario, mode and runs.");
    const scenarios = listScenarios(opts.scenarioDir);
    const entry = typeof raw.scenario === "string" ? scenarios.find((s) => s.id === raw.scenario) : undefined;
    if (!entry) throw new HttpError(400, "That scenario isn't one of the available scenarios.");
    if (raw.mode !== "on" && raw.mode !== "off") throw new HttpError(400, 'The mode must be "on" or "off".');
    const count = raw.runs === undefined ? 1 : raw.runs;
    if (typeof count !== "number" || !Number.isInteger(count) || count < 1 || count > MAX_RUNS) throw new HttpError(400, `Runs must be a whole number from 1 to ${MAX_RUNS}.`);
    if (raw.payload !== undefined && (typeof raw.payload !== "string" || raw.payload === "" || Buffer.byteLength(raw.payload) > MAX_PAYLOAD)) {
      throw new HttpError(400, `A custom payload must be non-empty text of at most ${MAX_PAYLOAD / 1024} KB.`);
    }
    if (typeof raw.model !== "string") throw new HttpError(400, "Choose a model, written provider/id.");
    let model: ModelRef;
    try {
      model = parseModel(raw.model);
    } catch (e) {
      throw new HttpError(400, (e as Error).message);
    }
    if (model.provider.toLowerCase() === "mistral") throw new HttpError(400, MISTRAL_NOTE);
    if (model.provider !== "ollama" && userAgentDir === undefined) {
      throw new HttpError(400, `Provider ${model.provider} needs your own pi setup: launch the demo with --agent-dir <your pi agent directory>.`);
    }
    return {
      settings: { model: raw.model, scenario: entry.id, mode: raw.mode, runs: count, ...(raw.payload !== undefined ? { payload: raw.payload as string } : {}) },
      model,
      entry,
    };
  }

  async function startRun(raw: unknown): Promise<ActiveRun> {
    const { settings, model, entry } = parseSettings(raw);
    if (active && !active.finished) throw new HttpError(409, "A run is already in progress. Wait for it to finish or cancel it.");
    const run: ActiveRun = {
      id: randomBytes(6).toString("hex"),
      settings,
      ac: new AbortController(),
      buffer: [],
      clients: new Set(),
      finished: false,
      cancelled: false,
      started: false,
      finishedPromise: Promise.resolve(),
    };
    // reserved before the first await, so two requests at once cannot both start
    active = run;
    try {
      await checkModelAvailable(model, doFetch);
    } catch (e) {
      active = undefined;
      throw new HttpError(400, (e as Error).message);
    }
    runs.set(run.id, run);
    for (const [id, r] of runs) {
      if (runs.size <= KEEP_RUNS) break;
      if (r.finished) runs.delete(id);
    }
    run.finishedPromise = execute(run, model, entry).catch(() => undefined);
    return run;
  }

  function emit(run: ActiveRun, event: string, data: unknown): void {
    run.buffer.push({ event, data });
    for (const c of run.clients) c.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  function finish(run: ActiveRun, data: unknown): void {
    emit(run, "done", data);
    run.finished = true;
    if (active === run) active = undefined;
    for (const c of run.clients) c.end();
    run.clients.clear();
  }

  function payloadFor(run: ActiveRun, entry: ScenarioEntry): { payload: Payload; payloadFile?: string } {
    const text = run.settings.payload;
    if (text === undefined) return { payload: { kind: "reference", sha256: sha256(readFileSync(entry.scenario.payloadFile)) } };
    mkdirSync(payloadDir, { recursive: true });
    const payloadFile = join(payloadDir, `${run.id}.md`);
    writeFileSync(payloadFile, text);
    return { payload: { kind: "custom", sha256: sha256(text) }, payloadFile };
  }

  async function execute(run: ActiveRun, model: ModelRef, entry: ScenarioEntry): Promise<void> {
    const { settings } = run;
    const name = `${settings.runs === 1 ? "single" : "eval"}-${stamp(new Date())}-${run.id}`;
    const dir = join(resultsRoot, name);
    try {
      const { payload, payloadFile } = payloadFor(run, entry);
      if (settings.runs === 1) await executeSingle(run, model, entry, name, dir, payload, payloadFile);
      else await executeEval(run, entry, name, dir, payloadFile);
    } catch (e) {
      const message = (e as Error).message;
      const started = run.started || (settings.runs > 1 && existsSync(join(dir, "results.json")));
      const error = started ? `the run stopped with an error: ${message}` : `the run could not be started: ${message}`;
      let steps: Step[] = [];
      try {
        if (started && run.stepsSoFar) steps = run.stepsSoFar();
      } catch {
        // the error is the message; steps are a bonus
      }
      finish(run, { status: "error", error, name, mode: settings.mode, started, cancelled: run.cancelled, steps, ...evidenceOf(dir) });
    }
  }

  async function executeSingle(run: ActiveRun, model: ModelRef, entry: ScenarioEntry, name: string, dir: string, payload: Payload, payloadFile: string | undefined): Promise<void> {
    mkdirSync(dir, { recursive: true });
    const { settings } = run;
    const scenario = entry.scenario;
    const logs: Logs = { transcript: [], events: [], outcome: [], evidence: [] };
    const sent = new Map<number, string>();
    const emitSteps = (complete: boolean, authoritative: boolean): { steps: Step[]; transcript: unknown[] } => {
      const use = authoritative ? fromDisk(logs, dir) : { ...logs, evidence: readJsonl(join(dir, "evidence.jsonl")) };
      const steps = buildSteps(scenario, use, { complete });
      for (const step of steps) {
        const text = JSON.stringify(step);
        if (sent.get(step.index) === text) continue;
        sent.set(step.index, text);
        emit(run, "step", step);
      }
      return { steps, transcript: use.transcript };
    };
    run.stepsSoFar = () => buildSteps(scenario, fromDisk(logs, dir), { complete: true });
    let pending: NodeJS.Immediate | undefined;
    const onLine = (file: LineFile, line: string) => {
      if (file !== "transcript" && file !== "events" && file !== "outcome") return;
      run.started = true;
      try {
        (logs[file] as unknown[]).push(JSON.parse(line));
      } catch {
        return;
      }
      pending ??= setImmediate(() => {
        pending = undefined;
        emitSteps(false, false);
      });
    };
    const spec: RunSpec = {
      scenarioDir: entry.dir,
      mode: settings.mode as RunMode,
      model,
      runDir: dir,
      demoDir,
      agentDir: userAgentDir ?? isolatedAgentDir,
      userAgentDir: userAgentDir !== undefined,
      timeoutMs,
      ...(payloadFile !== undefined ? { payloadFile } : {}),
    };
    let result: RunResult;
    try {
      result = await doRunOnce(spec, onLine, run.ac.signal);
    } finally {
      if (pending) clearImmediate(pending);
      pending = undefined;
    }
    // the final list goes out whole in `done`, so the page can replace whatever it built from the stream
    const final = emitSteps(true, true);
    const answer = finalAnswer(final.transcript);
    const evidence = evidenceOf(dir);
    const scored = scoreRunFile(join(dir, "outcome.jsonl"), result, 1, ".", join(dir, "transcript.jsonl"));
    const record = {
      formatVersion: 1,
      kind: "single",
      date: new Date().toISOString(),
      model,
      scenario: { id: scenario.id, title: scenario.title },
      mode: settings.mode,
      payload,
      tools: scenario.tools,
      result,
      scored,
      cancelled: run.cancelled,
      ...(answer !== undefined ? { finalAnswer: answer } : {}),
    };
    try {
      writeFileSync(join(dir, "demo-run.json"), JSON.stringify(record, null, 2) + "\n");
    } catch {
      // the run is shown either way; it just can't be reopened later
    }
    finish(run, {
      ...result,
      name,
      scored,
      payload,
      started: true,
      steps: final.steps,
      ...(answer !== undefined ? { finalAnswer: answer } : {}),
      ...evidence,
      refusalsNote: REFUSALS_NOTE,
      cancelled: run.cancelled,
    });
  }

  async function executeEval(run: ActiveRun, entry: ScenarioEntry, name: string, dir: string, payloadFile: string | undefined): Promise<void> {
    const { settings } = run;
    const options: EvalOptions = {
      model: settings.model,
      runs: settings.runs,
      modes: [settings.mode as RunMode],
      scenarioDir: entry.dir,
      ...(payloadFile !== undefined ? { payloadFile } : {}),
      ...(userAgentDir !== undefined ? { agentDir: userAgentDir } : {}),
      outDir: dir,
      timeoutMs,
      command: "demo",
    };
    let lastCount = -1;
    const poll = setInterval(() => {
      try {
        const r = JSON.parse(readFileSync(join(dir, "results.json"), "utf8")) as { runs?: unknown[]; requested?: { runs?: number; modes?: unknown[] } };
        const completed = Array.isArray(r.runs) ? r.runs.length : 0;
        if (completed === lastCount) return;
        lastCount = completed;
        emit(run, "progress", { completed, planned: settings.runs });
      } catch {
        // not written yet
      }
    }, PROGRESS_POLL_MS);
    try {
      const results: ResultsFile = await doRunEval(options, {
        signal: run.ac.signal,
        ...(opts.deps?.runOnce ? { runOnce: opts.deps.runOnce } : {}),
        checkModel: (m) => checkModelAvailable(m, doFetch),
        fetch: doFetch,
        log: (message) => emit(run, "progress", { message }),
      });
      run.started = true;
      const v = verifyOf(results.runs);
      finish(run, { ...results, name, started: true, ...v, ...folderVerify(dir, v.verifyStatus), refusalsNote: REFUSALS_NOTE, cancelled: run.cancelled });
    } finally {
      clearInterval(poll);
    }
  }

  /** The files are the record; what arrived by callback fills in for a log the run did not write. */
  function fromDisk(seen: Logs, dir: string): Logs {
    const disk = logsFromDir(dir);
    return {
      transcript: disk.transcript.length > 0 ? disk.transcript : seen.transcript,
      events: disk.events.length > 0 ? disk.events : seen.events,
      outcome: disk.outcome.length > 0 ? disk.outcome : seen.outcome,
      evidence: disk.evidence,
    };
  }

  // --- routes ---

  async function setup(): Promise<unknown> {
    const scenarios = listScenarios(opts.scenarioDir);
    const models: Obj[] = [];
    const termsNotes: Record<string, string> = {};
    let ollamaNote: string | undefined;
    try {
      const res = await doFetch(OLLAMA_TAGS, { signal: AbortSignal.timeout(2000) });
      if (!res.ok) throw new Error("not ok");
      const body = (await res.json()) as { models?: { name?: unknown }[] };
      const names = (body.models ?? []).map((m) => m.name).filter((x): x is string => typeof x === "string");
      for (const n of [...new Set(names)].sort()) models.push({ id: `ollama/${n}`, provider: "ollama", local: true, permitted: true });
    } catch {
      ollamaNote = "Ollama isn't reachable at 127.0.0.1:11434. Start it with `ollama serve`.";
    }
    if (userAgentDir !== undefined) {
      const hosted: { provider: string; id: string }[] = [];
      try {
        const file: unknown = JSON.parse(readFileSync(join(userAgentDir, "models.json"), "utf8"));
        const providers = isObj(file) && isObj(file.providers) ? file.providers : {};
        for (const [provider, def] of Object.entries(providers)) {
          if (provider === "ollama" || !isObj(def) || !Array.isArray(def.models)) continue;
          for (const m of def.models) if (isObj(m) && typeof m.id === "string") hosted.push({ provider, id: m.id });
        }
      } catch {
        // no models.json: nothing hosted to list
      }
      hosted.sort((a, b) => (a.provider + "/" + a.id < b.provider + "/" + b.id ? -1 : 1));
      for (const h of hosted) {
        const mistral = h.provider.toLowerCase() === "mistral";
        const note = mistral ? MISTRAL_NOTE : HOSTED_NOTE;
        termsNotes[h.provider] = note;
        models.push({ id: `${h.provider}/${h.id}`, provider: h.provider, local: false, permitted: !mistral, note });
      }
    }
    return {
      models,
      scenarios: scenarios.map((s) => ({ id: s.id, title: s.scenario.title, description: s.scenario.description, userPrompt: s.scenario.userPrompt })),
      toolsNote: TOOLS_NOTE,
      termsNotes,
      plainClasses: PLAIN_CLASS,
      table: { modeLabels: MODE_LABEL, definitions: DEFINITIONS, limits: LIMITS },
      refusalsNote: REFUSALS_NOTE,
      ...(ollamaNote !== undefined ? { ollamaNote } : {}),
    };
  }

  function summaryOf(f: Folder): Obj {
    const l = loadFolder(f.dir);
    if (!l.ok) return { name: f.name, ok: false, error: l.error };
    if (l.kind === "single") {
      const r = l.run;
      const ms = durationOf(r.result);
      const status = isObj(r.result) ? r.result.status : undefined;
      return {
        name: f.name,
        ok: true,
        kind: "single",
        date: r.date,
        model: r.model,
        scenario: r.scenario,
        mode: r.mode,
        payload: r.payload,
        ...(typeof status === "string" ? { status } : {}),
        cancelled: r.cancelled === true,
        ...(ms !== undefined && r.cancelled !== true ? { medianRunMs: ms } : {}),
      };
    }
    const r = l.results;
    const runs = r.runs as unknown[];
    const c = checkNow(f.dir, r);
    const checked =
      "error" in c
        ? { error: c.error }
        : { verifyStatus: c.verifyStatus, disagreements: c.recheck.disagreements.length, problems: c.recheck.problems.length };
    const ms = median(runs.flatMap((run) => (isObj(run) && typeof run.dir === "string" ? (durationOf(readJson(join(f.dir, run.dir, "run.json"))) ?? []) : [])));
    const modes = isObj(r.requested) && Array.isArray(r.requested.modes) ? r.requested.modes : undefined;
    return {
      name: f.name,
      ok: true,
      kind: "eval",
      date: r.date,
      model: r.model,
      scenario: r.scenario,
      payload: r.payload,
      incomplete: r.incomplete === true,
      runs: runs.length,
      checked,
      ...(modes !== undefined ? { modes } : {}),
      ...(ms !== undefined ? { medianRunMs: ms } : {}),
    };
  }

  type RunDetails = { stepsByRun: Record<string, Step[]>; stepsErrors: Record<string, string>; answersByRun: Record<string, string>; verifyCommands: Record<string, string> };
  function stepsForRuns(folder: Folder, results: Obj): RunDetails {
    const scenario = scenarioFor(isObj(results.scenario) && typeof results.scenario.id === "string" ? results.scenario.id : "");
    const stepsByRun: Record<string, Step[]> = {};
    const stepsErrors: Record<string, string> = {};
    const answersByRun: Record<string, string> = {};
    const verifyCommands: Record<string, string> = {};
    for (const r of results.runs as unknown[]) {
      if (!isObj(r) || typeof r.dir !== "string") continue;
      const runDir = resolve(folder.dir, r.dir);
      const rel = relative(folder.dir, runDir);
      if (rel === "" || rel.startsWith("..") || rel.split(sep).includes("..")) {
        stepsErrors[r.dir] = "This run's folder is outside the results folder, so it was not read.";
        continue;
      }
      if (!existsSync(runDir)) {
        stepsErrors[r.dir] = "This run's folder isn't there.";
        continue;
      }
      try {
        const logs = logsFromDir(runDir);
        stepsByRun[r.dir] = buildSteps(scenario, logs, { complete: true });
        const answer = finalAnswer(logs.transcript);
        if (answer !== undefined) answersByRun[r.dir] = answer;
      } catch (e) {
        stepsErrors[r.dir] = `This run's logs couldn't be read (${(e as Error).message}).`;
      }
      const ev = evidenceOf(runDir);
      if (ev.verifyCommand !== undefined) verifyCommands[r.dir] = ev.verifyCommand;
    }
    return { stepsByRun, stepsErrors, answersByRun, verifyCommands };
  }

  function resultDetail(name: string): { status: number; body: unknown } {
    const folder = folders().find((f) => f.name === name);
    if (!folder) return { status: 404, body: { error: "There is no results folder by that name." } };
    const l = loadFolder(folder.dir);
    if (!l.ok) return { status: 200, body: { name, ok: false, error: l.error } };
    if (l.kind === "single") {
      const dir = folder.dir;
      const logs = logsFromDir(dir);
      const answer = finalAnswer(logs.transcript);
      const steps = buildSteps(scenarioFor(String((l.run.scenario as Obj | undefined)?.id ?? "")), logs, { complete: true });
      return { status: 200, body: { ...l.run, name, ok: true, kind: "single", steps, ...(answer !== undefined ? { finalAnswer: answer } : {}), ...evidenceOf(dir), refusalsNote: REFUSALS_NOTE } };
    }
    const results = l.results;
    // what results.json says, as the eval recorded it; an older folder may not count runs that recorded
    // nothing, which is shown as not recorded, never as 0
    const stored = verifyOf(results.runs as unknown[]);
    const recorded = { note: RECORDED_NOTE, summary: results.summary, verify: results.verify, runs: results.runs, ...stored };
    const c = checkNow(folder.dir, results);
    if ("error" in c) {
      // nothing could be checked now: the stored figures are shown, labelled as recorded, and never as checked
      return {
        status: 200,
        body: { ...results, name, ok: true, kind: "eval", ...stepsForRuns(folder, results), ...stored, verifyStatus: "unknown", recorded, check: { checkedNow: false, error: c.error }, refusalsNote: REFUSALS_NOTE },
      };
    }
    const { recheck } = c;
    return {
      status: 200,
      body: {
        ...results,
        name,
        ...folderVerify(folder.dir, c.verifyStatus),
        ok: true,
        kind: "eval",
        ...stepsForRuns(folder, results),
        // the table, the runs and the evidence check are what the files say now
        summary: recheck.summary,
        verify: recheck.verify,
        runs: recheck.runs,
        verifyStatus: c.verifyStatus,
        verifyLine: c.verifyLine,
        recorded,
        check: { checkedNow: true, note: CHECKED_NOTE, disagreeNote: DISAGREE_NOTE, disagreements: recheck.disagreements, problems: recheck.problems, notes: recheck.notes },
        refusalsNote: REFUSALS_NOTE,
      },
    };
  }

  function stream(run: ActiveRun, req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", connection: "keep-alive", "x-content-type-options": "nosniff" });
    res.write(": connected\n\n");
    for (const e of run.buffer) res.write(`event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`);
    if (run.finished) {
      res.end();
      return;
    }
    run.clients.add(res);
    const beat = setInterval(() => res.write(": ping\n\n"), HEARTBEAT_MS);
    beat.unref();
    const cleanup = () => {
      clearInterval(beat);
      run.clients.delete(res);
    };
    res.on("close", cleanup);
    req.on("close", cleanup);
  }

  function serveStatic(pathname: string, res: ServerResponse, head: boolean): void {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      sendJson(res, 400, { error: "That address isn't valid." });
      return;
    }
    const file = resolve(PUBLIC_DIR, "." + (decoded === "/" ? "/index.html" : decoded));
    const rel = relative(PUBLIC_DIR, file);
    let ok = rel !== "" && !rel.startsWith("..") && !rel.split(sep).includes("..");
    try {
      ok = ok && statSync(file).isFile();
    } catch {
      ok = false;
    }
    if (!ok) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    res.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      // the page loads nothing from anywhere else, and no inline script or style
      "content-security-policy": "default-src 'self'",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    });
    res.end(head ? undefined : readFileSync(file));
  }

  async function api(req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> {
    const method = req.method ?? "GET";
    let m: RegExpExecArray | null;
    if (pathname === "/api/setup" && method === "GET") return sendJson(res, 200, await setup());
    if (pathname === "/api/runs" && method === "POST") {
      const run = await startRun(await readBody(req));
      return sendJson(res, 200, { id: run.id });
    }
    if ((m = /^\/api\/runs\/([^/]+)\/(stream|compare|cancel)$/.exec(pathname))) {
      const run = runs.get(m[1]!);
      if (!run) throw new HttpError(404, "There is no run with that id.");
      if (m[2] === "stream" && method === "GET") return stream(run, req, res);
      if (m[2] === "compare" && method === "POST") {
        const other = await startRun({ ...run.settings, mode: run.settings.mode === "on" ? "off" : "on" });
        return sendJson(res, 200, { id: other.id });
      }
      if (m[2] === "cancel" && method === "POST") {
        if (run.finished) return sendJson(res, 200, { ok: true, alreadyFinished: true });
        run.cancelled = true;
        run.ac.abort();
        return sendJson(res, 200, { ok: true });
      }
      throw new HttpError(405, "That method isn't supported here.");
    }
    if (pathname === "/api/results" && method === "GET") return sendJson(res, 200, folders().map(summaryOf));
    if ((m = /^\/api\/results\/([^/]+)$/.exec(pathname)) && method === "GET") {
      let name: string;
      try {
        name = decodeURIComponent(m[1]!);
      } catch {
        throw new HttpError(400, "That address isn't valid.");
      }
      const out = resultDetail(name);
      return sendJson(res, out.status, out.body);
    }
    throw new HttpError(404, "There is nothing at that address.");
  }

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const host = req.headers.host;
    // DNS rebinding: a page on another name can resolve to 127.0.0.1, but it cannot make the browser send this Host
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      sendJson(res, 403, { error: "This server only answers requests addressed to 127.0.0.1 or localhost on its own port." });
      return;
    }
    const method = req.method ?? "GET";
    if (url.pathname.startsWith("/api/")) {
      if (!keyMatches(req.headers["x-demo-key"], opts.key)) {
        sendJson(res, 403, { error: "The demo key is missing or wrong. Open the address the launcher printed, including the part after #." });
        return;
      }
      api(req, res, url.pathname).catch((e: unknown) => {
        const status = e instanceof HttpError ? e.status : 500;
        if (res.headersSent) {
          res.end();
          return;
        }
        sendJson(res, status, { error: e instanceof HttpError ? e.message : "The demo server hit a problem with that request." });
      });
      return;
    }
    if (method !== "GET" && method !== "HEAD") {
      sendJson(res, 405, { error: "That method isn't supported here." });
      return;
    }
    serveStatic(url.pathname, res, method === "HEAD");
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    async close() {
      const current = active;
      if (current && !current.finished) {
        current.cancelled = true;
        current.ac.abort();
        await current.finishedPromise;
      }
      for (const r of runs.values()) {
        for (const c of r.clients) c.end();
        r.clients.clear();
      }
      await new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      });
    },
  };
}
