// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Generates demo keys and signed policies: <out>/server (mcp-entry, github-tools) and <out>/client (session, pi).
// Prints only paths, never key material.

import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const AGENTS = join(import.meta.dirname, "..");
const KEYGEN = join(AGENTS, "policy-tool-ts/src/keygen.ts");
const POLICY = join(AGENTS, "policy-tool-ts/src/policy.ts");

function run(script: string, args: string[]): void {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  if (r.status !== 0) {
    console.error(r.stderr || r.stdout);
    process.exit(r.status ?? 1);
  }
}

function setup(dir: string, services: string, paths: string): void {
  run(KEYGEN, ["--out", dir, "--services", services]);
  run(POLICY, ["--paths", paths, "--policy-key", join(dir, "policy.key"), "--out", dir]);
  console.log(dir);
}

let out: string;
try {
  out = resolve(parseArgs({ options: { out: { type: "string" } }, strict: true }).values.out ?? join(AGENTS, ".demo"));
} catch (e) {
  console.error((e as Error).message);
  console.error("Usage: node setup-demo.ts [--out agents/.demo]");
  process.exit(2);
}
setup(join(out, "server"), "mcp-entry,github-tools", join(AGENTS, "policies/server.paths.yaml"));
setup(join(out, "client"), "session,pi", join(AGENTS, "policies/client.paths.yaml"));
