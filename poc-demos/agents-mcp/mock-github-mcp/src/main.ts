// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { parseArgs } from "node:util";
import type { ServerPolicy } from "@paztport/mcp";
import { OutcomeLog, type Mode } from "./outcome.ts";
import { loadServerConfig } from "./paztport.ts";
import { BUILTIN_SCENARIO_DIR, loadScenario, scenarioFixtures, type Scenario } from "./scenario.ts";
import { createGithubServer } from "./server.ts";
import { serveStdio } from "./stdio.ts";

const PKG = join(import.meta.dirname, "..");
const USAGE =
  "Usage: node main.ts --mode <enforce|audit|off> [--config <dir>] [--outcome-log <file>] [--canary <s>] [--payload <file>|none] [--scenario <dir>]\n" +
  "  --config defaults to agents/.demo/server (run `npm run setup-demo` in agents/ to create it)\n" +
  "  --scenario defaults to agents/scenarios/github-issue-replay";

function usage(message?: string): never {
  if (message) console.error(message);
  console.error(USAGE);
  process.exit(2);
}

function main(): void {
  let values: { mode?: string; config?: string; "outcome-log"?: string; canary?: string; payload?: string; scenario?: string };
  try {
    values = parseArgs({
      options: {
        mode: { type: "string" },
        config: { type: "string" },
        "outcome-log": { type: "string" },
        canary: { type: "string" },
        payload: { type: "string" },
        scenario: { type: "string" },
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

  let paztport: ServerPolicy | null = null;
  if (mode !== "off") {
    const dir = values.config ?? join(PKG, "../.demo/server");
    try {
      paztport = loadServerConfig(dir);
    } catch (e) {
      return usage(`cannot load Paztport config from ${dir}: ${(e as Error).message}`);
    }
  }

  const scenarioDir = values.scenario ?? BUILTIN_SCENARIO_DIR;
  let scenario: Scenario;
  try {
    scenario = loadScenario(scenarioDir);
  } catch (e) {
    return usage(`cannot load --scenario ${scenarioDir}: ${(e as Error).message}`);
  }

  const payloadArg = values.payload ?? scenario.payloadFile;
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
    state: scenarioFixtures(scenario, { canary, issuePayload }),
    outcome: new OutcomeLog(logPath, canary, scenario.markers),
    taskCheck: scenario.taskCheck,
  });
  console.error(`mock-github-mcp: mode=${mode} serving stdio`);
  void serveStdio(server, process.stdin, process.stdout);
}

main();
