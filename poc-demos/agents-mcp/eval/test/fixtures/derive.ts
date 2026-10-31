// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds the two fixture sets from real runs of `npm run eval -- --modes on,off` (a Paztport-on run that was blocked,
// and a Paztport-off run). Run it from poc-demos/agents-mcp/:
//
//   node eval/test/fixtures/derive.ts <on-run dir> <off-run dir>
//
// eval-results/ holds the on run as on-001, a copy of it with the repo in one signed call changed so that the call no
// longer matches its binding (on-002, the check must fail it), a copy cut down to its run record (on-003), the off run's
// outcome log (off-001) and the results.json that lists them. recorded-on-run/ (demo-ui) holds the on run with the
// transcript's thinking and answer text deltas dropped; nothing reads them and they are most of its size. Nothing
// else is edited.

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [onDir, offDir] = process.argv.slice(2);
if (onDir === undefined || offDir === undefined) {
  console.error("usage: node eval/test/fixtures/derive.ts <on-run dir> <off-run dir>");
  process.exit(2);
}
const here = import.meta.dirname;
const lines = (file: string): string[] => readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");

// eval-results
const results = join(here, "eval-results");
rmSync(join(results, "runs"), { recursive: true, force: true });
const on1 = join(results, "runs/on-001");
mkdirSync(on1, { recursive: true });
for (const f of ["events.jsonl", "evidence.jsonl", "outcome.jsonl"]) cpSync(join(onDir, f), join(on1, f));

const evidence = lines(join(onDir, "evidence.jsonl"));
let tampered = false;
const changed = evidence.map((l) => {
  const rec = JSON.parse(l);
  if (!tampered && rec.type === "call" && rec.params?.arguments?.repo === "payroll-notes") {
    rec.params.arguments.repo = "website";
    tampered = true;
  }
  return JSON.stringify(rec);
});
if (!tampered) throw new Error("no call on payroll-notes in the on run's evidence");
mkdirSync(join(results, "runs/on-002"), { recursive: true });
writeFileSync(join(results, "runs/on-002/evidence.jsonl"), changed.join("\n") + "\n");

const runRecord = evidence.filter((l) => JSON.parse(l).type === "run");
if (runRecord.length !== 1) throw new Error("expected one run record in the on run's evidence");
mkdirSync(join(results, "runs/on-003"), { recursive: true });
writeFileSync(join(results, "runs/on-003/evidence.jsonl"), runRecord[0] + "\n");

mkdirSync(join(results, "runs/off-001"), { recursive: true });
cpSync(join(offDir, "outcome.jsonl"), join(results, "runs/off-001/outcome.jsonl"));

const run = (mode: string, index: number, outcome: string, status: string, verify: string) =>
  ({ mode, index, dir: `runs/${mode}-${String(index).padStart(3, "0")}`, outcome, status, verify: { status: verify, problems: [] } });
writeFileSync(
  join(results, "results.json"),
  JSON.stringify(
    {
      formatVersion: 1,
      runs: [run("on", 1, "blocked", "completed", "ok"), run("on", 2, "blocked", "completed", "failed"), run("on", 3, "error", "error", "not-recorded"), run("off", 1, "resisted", "completed", "none")],
    },
    null,
    2,
  ) + "\n",
);

// demo-ui's recorded run
const rec = join(here, "../../../demo-ui/test/fixtures/recorded-on-run");
rmSync(rec, { recursive: true, force: true });
mkdirSync(rec, { recursive: true });
for (const f of ["canary.txt", "events.jsonl", "evidence.jsonl", "outcome.jsonl", "run.json"]) cpSync(join(onDir, f), join(rec, f));
const kept = lines(join(onDir, "transcript.jsonl")).filter((l) => {
  const t = JSON.parse(l).assistantMessageEvent?.type;
  return t !== "thinking_delta" && t !== "text_delta";
});
writeFileSync(join(rec, "transcript.jsonl"), kept.join("\n") + "\n");
