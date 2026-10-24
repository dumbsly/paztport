// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { createFixtures, PRIVATE_MARKERS } from "./fixtures.ts";
import { OutcomeLog, type Mode } from "./outcome.ts";
import { loadServerConfig, type ServerPaztportConfig } from "./paztport.ts";
import { createGithubServer } from "./server.ts";
import { serveStdio } from "./stdio.ts";

const PKG = join(import.meta.dirname, "..");
const USAGE =
  "Usage: node main.ts --mode <enforce|audit|off> [--config <dir>] [--outcome-log <file>] [--canary <s>] [--payload <file>|none]\n" +
  "  --config defaults to agents/.demo/server (run `npm run setup-demo` in agents/ to create it)";

function usage(message?: string): never {
  if (message) console.error(message);
  console.error(USAGE);
  process.exit(2);
}

function main(): void {
  let values: { mode?: string; config?: string; "outcome-log"?: string; canary?: string; payload?: string };
  try {
    values = parseArgs({
      options: {
        mode: { type: "string" },
        config: { type: "string" },
        "outcome-log": { type: "string" },
        canary: { type: "string" },
        payload: { type: "string" },
      },
      strict: true,
    }).values;
  } catch (e) {
    return usage((e as Error).message);
  }
  const mode = values.mode ?? "enforce";
  if (mode !== "enforce" && mode !== "audit" && mode !== "off") return usage(`invalid --mode: ${mode}`);
  const canary = values.canary ?? randomBytes(8).toString("hex");
  if (canary === "") return usage("--canary must be non-empty");

  let paztport: ServerPaztportConfig | null = null;
  if (mode !== "off") {
    const dir = values.config ?? join(PKG, "../.demo/server");
    try {
      paztport = loadServerConfig(dir);
    } catch (e) {
      return usage(`cannot load Paztport config from ${dir}: ${(e as Error).message}`);
    }
  }

  const payloadArg = values.payload ?? join(PKG, "payloads/issue-default.md");
  let issuePayload: string | null = null;
  if (payloadArg !== "none") {
    try {
      issuePayload = readFileSync(payloadArg, "utf8");
    } catch (e) {
      return usage(`cannot read --payload ${payloadArg}: ${(e as Error).message}`);
    }
  }

  const logPath = values["outcome-log"] ?? null;
  if (logPath !== null) {
    try {
      appendFileSync(logPath, ""); // fail at startup, not on the first write
    } catch (e) {
      return usage(`cannot write --outcome-log ${logPath}: ${(e as Error).message}`);
    }
  }

  const server = createGithubServer({
    mode: mode as Mode,
    paztport,
    state: createFixtures({ canary, issuePayload }),
    outcome: new OutcomeLog(logPath, canary, PRIVATE_MARKERS),
  });
  console.error(`mock-github-mcp: mode=${mode} serving stdio`);
  void serveStdio(server, process.stdin, process.stdout);
}

main();
