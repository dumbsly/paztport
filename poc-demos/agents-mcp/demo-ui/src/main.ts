// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Usage: npm run demo -- [--agent-dir <your pi agent dir>] [--results <folder>] [--no-open] [--unsafe-tool-usage]
//   --agent-dir  use your own pi setup, which allows hosted models (the page shows each provider's terms note)
//   --results    also list a results folder from somewhere else (for example a published one)
//   --no-open    print the address and do not open a browser
//   --unsafe-tool-usage  offer runs without Paztport for the scenario that gives the model a real shell (use only in a sandbox)
// Exit code: 0 on a clean stop, 1 when Ollama isn't running, 2 for a usage or setup problem.

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { readKeyringFile, readReplyCertFile, readRootFile } from "@paztport/core";
import { startDemoServer, type DemoServer } from "./server.ts";

const AGENTS = join(import.meta.dirname, "../..");
const NODE_FLOOR = "22.19";
const OLLAMA_TAGS = "http://127.0.0.1:11434/api/tags";
const USAGE = "usage: npm run demo -- [--agent-dir <your pi agent dir>] [--results <folder>] [--no-open] [--unsafe-tool-usage]";

export type Launched = DemoServer;
export type LaunchDeps = {
  fetch?: typeof fetch;
  log?: (s: string) => void;
  /** Opens the address in a browser. Tests pass a recorder; the default is best effort and never throws. */
  opener?: (url: string) => void;
  /** Makes the demo keys in `dir` if they are missing. */
  ensureKeys?: (dir: string) => void;
  paths?: { demoRoot: string; scenarioDir: string };
  nodeVersion?: string;
};

/** True when `version` ("22.19.1") is at least `floor` ("22.19"). */
export function nodeAtLeast(version: string, floor: string): boolean {
  const v = version.split(".").map(Number);
  const f = floor.split(".").map(Number);
  for (let i = 0; i < f.length; i++) {
    const a = v[i] ?? 0;
    if (a !== f[i]) return a > f[i]!;
  }
  return true;
}

/** Files setup-demo writes that only have to exist. Keys made by an earlier version can lack some, such as the local-tools policy. */
const KEY_FILES = ["client/server-policy.pub", "client/local-tools/rules.json"];

/** Files setup-demo writes that carry a `notAfter`, each with its SDK reader: keyrings, roots, reply certificate. */
const WINDOWED_FILES: readonly (readonly [string, (bytes: Uint8Array) => { notAfter: number }])[] = [
  ["server/keyring.json", readKeyringFile],
  ["server/root.json", readRootFile],
  ["client/keyring.json", readKeyringFile],
  ["client/root.json", readRootFile],
  ["client/local-tools/root.json", readRootFile],
  ["server/reply-cert.json", readReplyCertFile],
];

/** How long each keyring, root and the reply certificate must still have to run, so evidence a run saves still verifies afterwards. */
const POLICY_MARGIN_MS = 86_400_000;

/**
 * Whether `file` in `dir` reads, by `read`, and names a `notAfter` at least POLICY_MARGIN_MS from now: the mock server
 * refuses expired material, and material that does not read.
 */
function windowCurrent(dir: string, file: string, read: (bytes: Uint8Array) => { notAfter: number }): boolean {
  try {
    return Date.now() + POLICY_MARGIN_MS <= read(readFileSync(join(dir, file))).notAfter;
  } catch {
    return false;
  }
}

/** True when `dir` holds every file setup-demo writes, with every keyring, root and the reply certificate current for a day more, so the keys there can be used as they are. */
export function keysComplete(dir: string): boolean {
  return (
    KEY_FILES.every((f) => existsSync(join(dir, f))) && WINDOWED_FILES.every(([f, read]) => windowCurrent(dir, f, read))
  );
}

function defaultEnsureKeys(dir: string): void {
  if (keysComplete(dir)) return;
  const args = [join(AGENTS, "scripts/setup-demo.ts"), "--out", dir, ...(existsSync(dir) ? ["--force"] : [])];
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`Couldn't create the demo keys: ${(r.stderr || r.stdout || "setup-demo failed").trim()}`);
}

function defaultOpener(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // the address is printed either way
  }
}

async function ollamaUp(f: typeof fetch): Promise<boolean> {
  try {
    return (await f(OLLAMA_TAGS, { signal: AbortSignal.timeout(2000) })).ok;
  } catch {
    return false;
  }
}

/** Checks the setup, starts the server and opens the page. Returns the running server, or an exit code. */
export async function launch(argv: string[], deps: LaunchDeps = {}): Promise<Launched | { exitCode: number }> {
  const log = deps.log ?? ((s: string) => void process.stderr.write(s + "\n"));
  let v;
  try {
    v = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: { "agent-dir": { type: "string" }, results: { type: "string", multiple: true }, "no-open": { type: "boolean" }, "unsafe-tool-usage": { type: "boolean" } },
    }).values;
  } catch (e) {
    log((e as Error).message);
    log(USAGE);
    return { exitCode: 2 };
  }
  if (!nodeAtLeast(deps.nodeVersion ?? process.versions.node, NODE_FLOOR)) {
    log(`The demo needs Node ${NODE_FLOOR} or newer; this is Node ${deps.nodeVersion ?? process.versions.node}.`);
    return { exitCode: 2 };
  }
  const extraResults = (v.results ?? []).map((p) => resolve(p));
  for (const p of extraResults) {
    let isDir = false;
    try {
      isDir = statSync(p).isDirectory();
    } catch {
      // reported below
    }
    if (!isDir) {
      log(`${p} isn't a folder.`);
      return { exitCode: 2 };
    }
  }
  const userAgentDir = v["agent-dir"] !== undefined ? resolve(v["agent-dir"]) : undefined;
  if (userAgentDir !== undefined) {
    let isDir = false;
    try {
      isDir = statSync(userAgentDir).isDirectory();
    } catch {
      // reported below
    }
    if (!isDir) {
      log(`${userAgentDir} isn't a folder. --agent-dir must name your existing pi agent directory.`);
      return { exitCode: 2 };
    }
  }
  if (!(await ollamaUp(deps.fetch ?? fetch))) {
    if (userAgentDir === undefined) {
      log("Ollama isn't reachable at 127.0.0.1:11434. Start it with `ollama serve`, then run the demo again.");
      return { exitCode: 1 };
    }
    log("Ollama isn't reachable at 127.0.0.1:11434, so local models can't be used. Hosted models from your agent dir still can.");
  }

  const demoRoot = deps.paths?.demoRoot ?? join(AGENTS, ".demo");
  const keysDir = join(demoRoot, "demo-keys");
  try {
    (deps.ensureKeys ?? defaultEnsureKeys)(keysDir);
  } catch (e) {
    log((e as Error).message);
    return { exitCode: 2 };
  }
  const key = randomBytes(32).toString("base64url");
  const server = await startDemoServer({
    resultsRoot: join(demoRoot, "results"),
    demoDir: keysDir,
    scenarioDir: deps.paths?.scenarioDir ?? join(AGENTS, "scenarios"),
    key,
    ...(userAgentDir !== undefined ? { userAgentDir } : {}),
    extraResults,
    ...(v["unsafe-tool-usage"] ? { unsafeToolUsage: true } : {}),
    ...(deps.fetch ? { deps: { fetch: deps.fetch } } : {}),
  });
  const url = `${server.url}/#key=${key}`;
  log(`The demo is running at ${url}`);
  log("The address carries a key that lets the page start runs. Keep it to yourself, and press Ctrl-C to stop the demo.");
  if (userAgentDir !== undefined) log("You started the demo with your own pi agent dir. A hosted model receives the run's prompts and tool results under its provider's terms.");
  if (v["unsafe-tool-usage"]) log("You started the demo with --unsafe-tool-usage. The scenario with local tools can be run with Paztport off, and then the model has a real shell on this machine. Use that only in a sandbox.");
  if (!v["no-open"]) (deps.opener ?? defaultOpener)(url);
  return { url, close: server.close };
}

if (import.meta.main) {
  const r = await launch(process.argv.slice(2));
  if ("exitCode" in r) {
    process.exitCode = r.exitCode;
  } else {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      void r.close().then(() => process.exit(0));
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  }
}
