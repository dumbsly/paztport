// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Usage: node eval/src/eval-main.ts --model provider/id [--runs N | --quick] [--modes a,b] [--scenario dir]
//   [--payload file] [--agent-dir dir] [--out dir] [--timeout seconds]
//   [--unsafe-tool-usage]
// Exit code: 0 finished, 1 finished but some evidence did not verify, 2 usage or setup problem, 130 interrupted.

import { rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { BUILTIN_SCENARIO_DIR, loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { keysDirFor, runEval, type EvalDeps, type EvalOptions } from "./eval.ts";
import { OFF_MODE_COPY, parseModel, type RunMode } from "./runner.ts";

const AGENTS = join(import.meta.dirname, "../..");
const ALL_MODES: RunMode[] = ["off", "on", "clean-off", "clean-on", "warning"];
/** The modes a scenario with a real shell runs without --unsafe-tool-usage. */
const LOCAL_SAFE_MODES: RunMode[] = ["on", "clean-on"];
const DEFAULT_RUNS = 20;
const QUICK_RUNS = 3;
const DEFAULT_TIMEOUT_S = 600;
const USAGE = `usage: eval --model provider/id [--runs N | --quick] [--modes ${ALL_MODES.join(",")}]
            [--scenario dir] [--payload file] [--agent-dir dir] [--out dir] [--timeout seconds]
            [--unsafe-tool-usage]`;

class UsageError extends Error {}

const pad = (n: number) => String(n).padStart(2, "0");
const stamp = (d: Date) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
const shellWord = (s: string) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`);

/** Reads the command line. `ctx.npm` says it was started as `npm run eval`, which is recorded as the command. */
export function parseCli(argv: string[], ctx: { cwd?: string; now?: Date; npm?: boolean } = {}): EvalOptions {
  let v;
  try {
    v = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        model: { type: "string" },
        runs: { type: "string" },
        quick: { type: "boolean" },
        modes: { type: "string" },
        scenario: { type: "string" },
        payload: { type: "string" },
        "agent-dir": { type: "string" },
        out: { type: "string" },
        timeout: { type: "string" },
        "unsafe-tool-usage": { type: "boolean" },
      },
    }).values;
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  const cwd = ctx.cwd ?? process.cwd();
  const path = (p: string) => resolve(cwd, p);
  if (v.model === undefined) throw new UsageError("--model provider/id is required, for example --model ollama/qwen3:4b");
  let model;
  try {
    model = parseModel(v.model);
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  if (model.provider.toLowerCase() === "mistral") throw new UsageError("Mistral's hosted API is not permitted for this eval.");
  if (v.quick && v.runs !== undefined) throw new UsageError("use --quick or --runs, not both");
  let runs = v.quick ? QUICK_RUNS : DEFAULT_RUNS;
  if (v.runs !== undefined) {
    runs = Number(v.runs);
    if (!/^\d+$/.test(v.runs) || runs < 1) throw new UsageError(`--runs must be a whole number of at least 1 (got "${v.runs}")`);
  }
  const scenarioDir = v.scenario !== undefined ? path(v.scenario) : BUILTIN_SCENARIO_DIR;
  // a scenario that cannot be loaded is reported by the eval itself; here it only decides the defaults
  let localTools = false;
  try {
    localTools = loadScenario(scenarioDir).localTools === true;
  } catch {
    // reported later
  }
  const unsafeToolUsage = v["unsafe-tool-usage"] === true;
  const modes = v.modes === undefined ? (localTools && !unsafeToolUsage ? LOCAL_SAFE_MODES : [...ALL_MODES]) : (v.modes.split(",").map((m) => m.trim()) as RunMode[]);
  for (const m of modes) if (!ALL_MODES.includes(m)) throw new UsageError(`unknown mode "${m}" (modes: ${ALL_MODES.join(", ")})`);
  if (new Set(modes).size !== modes.length) throw new UsageError("--modes must not repeat a mode");
  if (localTools && !unsafeToolUsage && modes.some((m) => !LOCAL_SAFE_MODES.includes(m))) throw new UsageError(OFF_MODE_COPY);
  const seconds = v.timeout === undefined ? DEFAULT_TIMEOUT_S : Number(v.timeout);
  if (!Number.isFinite(seconds) || seconds <= 0) throw new UsageError(`--timeout must be a positive number of seconds (got "${v.timeout}")`);

  const safeId = model.id.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  const outDir = v.out !== undefined ? path(v.out) : join(AGENTS, ".demo/results", `${stamp(ctx.now ?? new Date())}-${safeId}`);
  return {
    model: v.model,
    runs,
    modes,
    scenarioDir,
    ...(v.payload !== undefined ? { payloadFile: path(v.payload) } : {}),
    ...(v["agent-dir"] !== undefined ? { agentDir: path(v["agent-dir"]) } : {}),
    outDir,
    timeoutMs: seconds * 1000,
    unsafeToolUsage,
    command: `${ctx.npm ? "npm run eval --" : "node eval/src/eval-main.ts"} ${argv.map(shellWord).join(" ")}`.trimEnd(),
  };
}

type Signals = { on(event: string, fn: () => void): unknown; off(event: string, fn: () => void): unknown };
export type MainDeps = Pick<EvalDeps, "runOnce" | "checkModel" | "fetch" | "log"> & { signals?: Signals; exit?: (code: number) => void };

/**
 * Runs the eval. pi runs in its own process group, so Ctrl-C does not reach it; SIGINT and SIGTERM
 * here abort the current run instead, and the results written so far are kept (incomplete: true).
 * A second signal removes the eval's keys folder, then stops at once.
 */
export async function main(argv: string[], deps: MainDeps = {}): Promise<number> {
  const log = deps.log ?? ((s: string) => void process.stderr.write(s + "\n"));
  let opts: EvalOptions;
  try {
    opts = parseCli(argv, { npm: process.env.npm_lifecycle_event === "eval" });
  } catch (e) {
    log((e as Error).message);
    log(USAGE);
    return 2;
  }
  const ac = new AbortController();
  const signals: Signals = deps.signals ?? process;
  let seen = 0;
  const onSignal = () => {
    if (++seen > 1) {
      // stopping at once skips the eval's own clean-up, so the private keys are removed here first
      const keys = keysDirFor(opts.outDir);
      try {
        rmSync(keys, { recursive: true, force: true });
      } catch {
        log(`Could not remove the keys folder; delete it yourself: ${keys}`);
      }
      (deps.exit ?? process.exit)(130);
      return;
    }
    log("Stopping: ending the current run and writing the results so far. Press Ctrl-C again to stop at once.");
    ac.abort();
  };
  signals.on("SIGINT", onSignal);
  signals.on("SIGTERM", onSignal);
  try {
    const results = await runEval(opts, { ...(deps.runOnce ? { runOnce: deps.runOnce } : {}), ...(deps.checkModel ? { checkModel: deps.checkModel } : {}), ...(deps.fetch ? { fetch: deps.fetch } : {}), signal: ac.signal, log });
    log(`Results: ${join(opts.outDir, "summary.md")}`);
    if (ac.signal.aborted) {
      log(`Not finished: ${results.runs.length} runs are recorded.`);
      return 130;
    }
    if (results.incomplete) {
      log(`Not finished: ${results.runs.length} runs are recorded.`);
      return 1;
    }
    if (results.verify.failed > 0) {
      log(`${results.verify.failed} runs have evidence that did not verify; summary.md says which.`);
      return 1;
    }
    return 0;
  } catch (e) {
    log((e as Error).message);
    return 2;
  } finally {
    signals.off("SIGINT", onSignal);
    signals.off("SIGTERM", onSignal);
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}
