// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { prepareAgentDir, type ModelRef } from "./models.ts";
import { redactFile, withRealPath, type Redaction } from "./redact.ts";

export { checkModelAvailable, parseModel, prepareAgentDir, type ModelRef } from "./models.ts";

export type RunMode = "off" | "on" | "clean-off" | "clean-on" | "warning";
export type RunSpec = {
  scenarioDir: string;
  mode: RunMode;
  model: ModelRef;
  runDir: string;
  /** Holds client/ and server/ keys. */
  demoDir: string;
  agentDir: string;
  /** The agent dir is the user's own: hosted keys stay in the environment and models.json is not touched. */
  userAgentDir: boolean;
  timeoutMs: number;
  /** A custom payload file. Ignored in the clean modes, which send none. */
  payloadFile?: string;
  /** Used only in mode "warning". */
  warning?: { file: string };
  /** Default: the installed pi 1.4.0 cli.js. */
  piCli?: string;
  /** Allows the modes without Paztport on a scenario that gives the model a real shell. */
  unsafeToolUsage?: boolean;
};
export type RunResult = { status: "completed" | "timeout" | "error"; exitCode: number | null; durationMs: number; canary: string; mode: RunMode };
export type LineFile = "transcript" | "events" | "outcome" | "stderr";

const AGENTS = resolve(import.meta.dirname, "../..");
const PI_CLI = join(AGENTS, "node_modules/@earendil-works/pi-coding-agent/dist/cli.js");
const EXTENSION = join(AGENTS, "pi-extension");
const MOCK_MAIN = join(AGENTS, "mock-github-mcp/src/main.ts");
const MODES: readonly RunMode[] = ["off", "on", "clean-off", "clean-on", "warning"];
const HOSTED_KEYS = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "MISTRAL_API_KEY", "OPENROUTER_API_KEY"];
/** Environment variables pi keeps in a local-tools run (the run's own HOME and PI_CODING_AGENT_DIR are added). */
const ENV_ALLOWLIST = ["PATH", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR"];
/** What a run without Paztport on a local-tools scenario is refused with. */
export const OFF_MODE_COPY = "This scenario gives the model a real shell on this machine, so runs without Paztport are offered only with --unsafe-tool-usage. Use that only in a sandbox.";
const KILL_GRACE_MS = 5000;
const CLOSE_GRACE_MS = 2000;
const POLL_MS = 100;

/** Splits a byte stream into lines; `end` returns an unterminated last line. */
class LineSplitter {
  #rest = "";
  push(chunk: string): string[] {
    const parts = (this.#rest + chunk).split("\n");
    this.#rest = parts.pop() ?? "";
    return parts.filter((l) => l !== "");
  }
  end(): string[] {
    const last = this.#rest;
    this.#rest = "";
    return last === "" ? [] : [last];
  }
}

/** Reads what a file gained since the last poll. */
class Tail {
  #offset = 0;
  readonly #split = new LineSplitter();
  readonly #decoder = new StringDecoder("utf8");
  readonly path: string;
  constructor(path: string) {
    this.path = path;
  }
  poll(): string[] {
    let size: number;
    try {
      size = statSync(this.path).size;
    } catch {
      return [];
    }
    if (size <= this.#offset) return [];
    const buf = Buffer.alloc(size - this.#offset);
    const fd = openSync(this.path, "r");
    try {
      readSync(fd, buf, 0, buf.length, this.#offset);
    } finally {
      closeSync(fd);
    }
    this.#offset = size;
    return this.#split.push(this.#decoder.write(buf));
  }
  end(): string[] {
    const polled = this.poll();
    return [...polled, ...this.#split.push(this.#decoder.end()), ...this.#split.end()];
  }
}

/** Process groups of running pi processes, killed if the eval exits without finishing them. */
const liveGroups = new Set<number>();
let exitHookInstalled = false;
function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const pid of liveGroups) {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // already gone
      }
    }
  });
}

function validate(spec: RunSpec): void {
  if (!MODES.includes(spec.mode)) throw new Error(`invalid run mode: ${String(spec.mode)}`);
  if (typeof spec.timeoutMs !== "number" || !Number.isFinite(spec.timeoutMs) || spec.timeoutMs <= 0) throw new Error("timeoutMs must be a positive number");
  for (const k of ["scenarioDir", "runDir", "demoDir", "agentDir"] as const) {
    if (typeof spec[k] !== "string" || spec[k] === "") throw new Error(`${k} must be a non-empty path`);
  }
  if (!spec.model || !spec.model.provider || !spec.model.id) throw new Error("model must name a provider and an id");
  if (spec.mode === "warning" && !spec.warning?.file) throw new Error("mode warning needs a warning file");
  if (spec.mode === "warning" && !existsSync(spec.warning!.file)) throw new Error(`warning file not found: ${spec.warning!.file}`);
  if (spec.payloadFile !== undefined && !existsSync(spec.payloadFile)) throw new Error(`payload file not found: ${spec.payloadFile}`);
}

/**
 * One stock pi run against the mock server for one scenario mode. Throws only for an invalid spec; a pi
 * that fails to start, exits non-zero, times out or is aborted comes back as a result.
 */
export async function runOnce(spec: RunSpec, onLine?: (file: LineFile, line: string) => void, signal?: AbortSignal): Promise<RunResult> {
  validate(spec);
  const scenario = loadScenario(spec.scenarioDir);
  if (scenario.localTools && spec.mode !== "on" && spec.mode !== "clean-on" && !spec.unsafeToolUsage) throw new Error(OFF_MODE_COPY);
  prepareAgentDir(spec.agentDir, spec.model, spec.userAgentDir);

  const runDir = resolve(spec.runDir);
  const demoDir = resolve(spec.demoDir);
  const scenarioDir = resolve(spec.scenarioDir);
  const workspace = join(runDir, "workspace");
  rmSync(workspace, { recursive: true, force: true });
  mkdirSync(workspace, { recursive: true });
  for (const [rel, text] of Object.entries(scenario.workspace?.files ?? {})) {
    const file = join(workspace, rel);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text);
  }
  const path = (name: string) => join(runDir, name);
  const enforced = spec.mode === "on" || spec.mode === "clean-on";
  // without Paztport nothing is signed, so those runs get no evidence log at all
  for (const f of ["transcript.jsonl", "events.jsonl", ...(enforced ? ["evidence.jsonl"] : []), "outcome.jsonl", "stderr.txt"]) writeFileSync(path(f), "");
  if (!enforced) rmSync(path("evidence.jsonl"), { force: true });

  const canary = randomBytes(8).toString("hex");
  writeFileSync(path("canary.txt"), canary + "\n");

  const serverMode = enforced ? "enforce" : "off";
  const payloadArg = spec.mode === "clean-on" || spec.mode === "clean-off" ? "none" : spec.payloadFile ? resolve(spec.payloadFile) : undefined;
  const serverArgs = [
    MOCK_MAIN,
    "--mode", serverMode,
    ...(enforced ? ["--config", join(demoDir, "server")] : []),
    "--outcome-log", path("outcome.jsonl"),
    "--canary", canary,
    "--scenario", scenarioDir,
    ...(payloadArg !== undefined ? ["--payload", payloadArg] : []),
  ];
  writeFileSync(
    path("config.json"),
    JSON.stringify(
      {
        mode: enforced ? "enforce" : "off",
        clientDir: join(demoDir, "client"),
        ...(scenario.localTools ? { clientPolicyDir: join(demoDir, "client", scenario.clientPolicy!) } : {}),
        eventsLog: path("events.jsonl"),
        ...(enforced ? { evidenceLog: path("evidence.jsonl") } : {}),
        servers: [{ id: scenario.serverId, command: process.execPath, args: serverArgs, attested: enforced }],
      },
      null,
      2,
    ) + "\n",
  );

  const args = [
    spec.piCli ?? PI_CLI,
    "-e", EXTENSION,
    "--paztport-config", path("config.json"),
    "--provider", spec.model.provider,
    "--model", spec.model.id,
    "--tools", scenario.tools,
    "--no-session",
    "--mode", "json",
    // Nothing outside the run folder reaches the model: no AGENTS.md/CLAUDE.md from the cwd or its parents,
    // no skills or prompt templates, no user mcp.json and no discovered extensions. The explicit -e extension
    // still loads (checked against pi 1.4.0's --help) and starts the only MCP server.
    "--no-context-files", "--no-skills", "--no-prompt-templates", "--no-mcp", "--no-extensions",
    ...(spec.mode === "warning" ? ["--append-system-prompt", resolve(spec.warning!.file)] : []),
    "--",
    scenario.userPrompt,
  ];
  let env: NodeJS.ProcessEnv;
  if (scenario.localTools) {
    // pi's tools run here as the user: build the environment from an allowlist, with a home of its own, so no
    // token, agent socket or config of the user's reaches them
    const home = path("home");
    mkdirSync(home, { recursive: true });
    env = { HOME: home, PI_CODING_AGENT_DIR: resolve(spec.agentDir) };
    for (const k of ENV_ALLOWLIST) if (process.env[k] !== undefined) env[k] = process.env[k];
    if (spec.userAgentDir) for (const k of HOSTED_KEYS) if (process.env[k] !== undefined) env[k] = process.env[k];
  } else {
    env = { ...process.env, PI_CODING_AGENT_DIR: resolve(spec.agentDir) };
    if (!spec.userAgentDir) for (const k of HOSTED_KEYS) delete env[k];
  }

  // A monotonic clock, as the time limit's timer uses: a wall clock that jumps (a machine waking from sleep, a
  // clock change) cannot make a run's duration disagree with its limit. On macOS and Linux neither counts time asleep.
  const finish = (status: RunResult["status"], exitCode: number | null, startedAt: number): RunResult => {
    const result: RunResult = { status, exitCode, durationMs: Math.round(performance.now() - startedAt), canary, mode: spec.mode };
    writeFileSync(path("run.json"), JSON.stringify(result, null, 2) + "\n");
    return result;
  };
  const startedAt = performance.now();
  if (signal?.aborted) return finish("error", null, startedAt);

  const emit = (file: LineFile, lines: string[]) => {
    if (!onLine) return;
    for (const l of lines) {
      try {
        onLine(file, l);
      } catch {
        // a failing listener must not stop the run or leave pi running
      }
    }
  };
  const out = new LineSplitter();
  const err = new LineSplitter();
  const tails: [LineFile, Tail][] = [
    ["events", new Tail(path("events.jsonl"))],
    ["outcome", new Tail(path("outcome.jsonl"))],
  ];

  const child = spawn(process.execPath, args, { cwd: workspace, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  if (child.pid !== undefined) {
    installExitHook();
    liveGroups.add(child.pid);
  }

  // The group kill reaches pi and anything that stayed in its group. It does not reach MCP servers: pi-mcp
  // starts each in its own process group. Those end because their stdin closes when pi dies, which the mock
  // server relies on; an MCP server that ignores stdin EOF would outlive a killed run.
  const killGroup = (sig: NodeJS.Signals) => {
    if (child.pid === undefined) return;
    try {
      process.kill(-child.pid, sig);
    } catch {
      // the group is already gone
    }
  };
  let reason: "timeout" | "abort" | null = null;
  let faulted = false;
  let exited = false;
  let escalation: NodeJS.Timeout | undefined;
  const terminate = (why: "timeout" | "abort" | "fault") => {
    if (why === "fault") faulted = true;
    else if (reason === null && !exited) reason = why;
    // one SIGTERM and one SIGKILL timer per run, however many faults or signals follow
    if (escalation !== undefined || exited) return;
    killGroup("SIGTERM");
    escalation = setTimeout(() => killGroup("SIGKILL"), KILL_GRACE_MS);
  };
  /** A run file that cannot be written or read ends the run as an error; it never throws out of an event handler. */
  const guard = (fn: () => void) => {
    try {
      fn();
    } catch (e) {
      if (!faulted) {
        try {
          appendFileSync(path("stderr.txt"), `runner: ${(e as Error).message}\n`);
        } catch {
          // stderr.txt is the broken file too
        }
      }
      terminate("fault");
    }
  };

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    guard(() => appendFileSync(path("transcript.jsonl"), chunk));
    emit("transcript", out.push(chunk));
  });
  child.stderr.on("data", (chunk: string) => {
    guard(() => appendFileSync(path("stderr.txt"), chunk));
    emit("stderr", err.push(chunk));
  });
  const poller = setInterval(() => {
    for (const [file, tail] of tails) guard(() => emit(file, tail.poll()));
  }, POLL_MS);

  const timer = setTimeout(() => terminate("timeout"), spec.timeoutMs);
  const onAbort = () => terminate("abort");
  signal?.addEventListener("abort", onAbort, { once: true });

  let exitCode: number | null = null;
  let spawnFailed = false;
  await new Promise<void>((done) => {
    child.on("error", (e) => {
      if (child.pid === undefined) {
        spawnFailed = true;
        guard(() => appendFileSync(path("stderr.txt"), `could not start pi: ${e.message}\n`));
        done();
      }
    });
    child.on("exit", (code) => {
      exited = true;
      exitCode = code;
      clearTimeout(escalation);
      // catches anything that stayed in pi's group and outlived it, and releases the pipes
      killGroup("SIGKILL");
      setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
        done();
      }, CLOSE_GRACE_MS).unref();
    });
    child.on("close", () => done());
  });

  clearTimeout(timer);
  clearTimeout(escalation);
  clearInterval(poller);
  if (child.pid !== undefined) liveGroups.delete(child.pid);
  signal?.removeEventListener("abort", onAbort);
  emit("transcript", out.end());
  emit("stderr", err.end());
  for (const [file, tail] of tails) guard(() => emit(file, tail.end()));

  // Published run folders should not carry the user's name or folder layout. pi writes absolute paths (its
  // session header's cwd, errors); scoring reads only tool names and stop reasons, so this changes no result.
  const redactions: Redaction[] = [
    { path: workspace, placeholder: "<workspace>" },
    { path: runDir, placeholder: "<run-dir>" },
    { path: AGENTS, placeholder: "<agents>" },
    { path: homedir(), placeholder: "<home>" },
  ].flatMap(withRealPath);
  for (const f of ["transcript.jsonl", "stderr.txt"]) {
    try {
      redactFile(path(f), redactions);
    } catch (e) {
      // the run's result stands; the file keeps its paths, and stderr.txt says so
      try {
        appendFileSync(path("stderr.txt"), `runner: could not remove absolute paths from ${f}: ${(e as Error).message}\n`);
      } catch {
        // stderr.txt is the broken file
      }
    }
  }

  const status: RunResult["status"] =
    reason === "timeout" ? "timeout" : reason === "abort" || spawnFailed || faulted ? "error" : exitCode === 0 ? "completed" : "error";
  return finish(status, exitCode, startedAt);
}
