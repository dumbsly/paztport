// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Shared test setup: demo keys from scripts/setup-demo.ts and the real mock servers.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const MOCK = join(import.meta.dirname, "../../../mock-github-mcp/src");
export const MAIN = join(MOCK, "main.ts");
export const DOCS = join(MOCK, "docs-main.ts");
export const STUB = join(import.meta.dirname, "stub-server.ts");
const SETUP = join(import.meta.dirname, "../../../scripts/setup-demo.ts");
export const CANARY = "c0ffee";

/** Generates demo keys and policies into <dir>/demo (server/ and client/) and returns that path. */
export function setupDemo(dir: string): string {
  const demo = join(dir, "demo");
  const r = spawnSync(process.execPath, [SETUP, "--out", demo], { encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`setup-demo failed: ${r.stderr}`);
  }
  return demo;
}

/** Arguments for the mock GitHub server (run with process.execPath). */
export function githubArgs(demo: string, mode: "enforce" | "audit" | "off", outcomeLog: string): string[] {
  return [MAIN, "--mode", mode, "--config", join(demo, "server"), "--outcome-log", outcomeLog, "--canary", CANARY];
}

/** The lines of a JSONL file, parsed. */
export const records = (path: string): Record<string, any>[] =>
  readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
