// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The scripted run the committed fixtures are made from: the real eval, pi, extension and mock server, with a stub in
// place of the model (stub-model.ts) replaying scripted-run.json, the tool calls of a run recorded with
// gemma4:26b-mlx on 2026-10-31 and then a final answer. The same script runs with Paztport on and off. Run it from
// poc-demos/agents-mcp/ to regenerate both fixture sets:
//
//   node eval/test/fixtures/record.ts
//
// It records into a temporary folder, derives eval-results/ and demo-ui's recorded-on-run/ from it (derive.ts), and
// rebuilds the five expected files beside them from verify, as the tests that read them build their reports:
//   - expected-folder-report.json and expected-file-report.json (eval-results) and expected-verify-report.json
//     (recorded-on-run): `JSON.stringify(report, null, 2) + "\n"` for verifyResultsDir of the folder or verifyEvidence
//     of an evidence.jsonl, the fixture's path replaced by `<fixture>`;
//   - expected-folder-stdout.txt and expected-file-stdout.txt: what `npm run verify -- <folder>` and
//     `npm run verify -- <folder>/runs/on-001/evidence.jsonl` print, the fixture's path replaced by `<fixture>` in the
//     second.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../src/eval-main.ts";
import { verifyEvidence, verifyResultsDir } from "../../src/verify.ts";
import { derive } from "./derive.ts";
import { startStubModel, type StubTurn } from "./stub-model.ts";

const SCRIPT = join(import.meta.dirname, "scripted-run.json");
const EVAL_RESULTS = join(import.meta.dirname, "eval-results");
const RECORDED_ON_RUN = join(import.meta.dirname, "../../../demo-ui/test/fixtures/recorded-on-run");
const VERIFY_MAIN = join(import.meta.dirname, "../../src/verify-main.ts");

/**
 * Runs the eval for modes on,off, one run each, against the stub, into `outDir`; returns the eval's exit code. The
 * eval's progress lines go to `log` (default: stderr).
 */
export async function record(outDir: string, log?: (line: string) => void): Promise<number> {
  const script = JSON.parse(readFileSync(SCRIPT, "utf8")) as StubTurn[];
  const stub = await startStubModel(script);
  // the eval leaves a user's agent folder alone, so the stub provider is named in one of our own
  const agentDir = mkdtempSync(join(tmpdir(), "paztport-stub-agent-"));
  try {
    const models = { providers: { stub: { baseUrl: stub.baseUrl, api: "openai-completions", apiKey: "stub", models: [{ id: "replay" }] } } };
    writeFileSync(join(agentDir, "models.json"), JSON.stringify(models, null, 2) + "\n");
    const argv = ["--model", "stub/replay", "--agent-dir", agentDir, "--modes", "on,off", "--runs", "1", "--out", outDir];
    return await main(argv, log !== undefined ? { log } : {});
  } finally {
    await stub.close();
    rmSync(agentDir, { recursive: true, force: true });
  }
}

const reportText = (report: unknown) => JSON.stringify(report, null, 2) + "\n";
const verifyStdout = (target: string) => spawnSync(process.execPath, [VERIFY_MAIN, target], { encoding: "utf8" }).stdout;

if (import.meta.main) {
  const tmp = mkdtempSync(join(tmpdir(), "paztport-record-"));
  try {
    const out = join(tmp, "results");
    const code = await record(out);
    if (code !== 0) throw new Error(`the eval exited with code ${code}; the fixtures are left as they were`);
    derive(out, "on-001", "off-001");
    const file = join(EVAL_RESULTS, "runs/on-001/evidence.jsonl");
    writeFileSync(join(EVAL_RESULTS, "expected-folder-report.json"), reportText(verifyResultsDir(EVAL_RESULTS)));
    writeFileSync(join(EVAL_RESULTS, "expected-file-report.json"), reportText(verifyEvidence(file)).replaceAll(EVAL_RESULTS, "<fixture>"));
    writeFileSync(join(EVAL_RESULTS, "expected-folder-stdout.txt"), verifyStdout(EVAL_RESULTS));
    writeFileSync(join(EVAL_RESULTS, "expected-file-stdout.txt"), verifyStdout(file).replaceAll(EVAL_RESULTS, "<fixture>"));
    const recorded = reportText(verifyEvidence(join(RECORDED_ON_RUN, "evidence.jsonl"))).replaceAll(RECORDED_ON_RUN, "<fixture>");
    writeFileSync(join(RECORDED_ON_RUN, "expected-verify-report.json"), recorded);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
