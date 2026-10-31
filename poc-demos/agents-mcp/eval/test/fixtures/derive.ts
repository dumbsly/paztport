// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds the two fixture sets from one results folder of `npm run eval -- --modes on,off`, a Paztport-on run that the
// server blocked and a Paztport-off run. Run it from poc-demos/agents-mcp/:
//
//   node eval/test/fixtures/derive.ts <results folder> <on run, e.g. on-001> <off run, e.g. off-002>
//
// eval-results/ holds the on run as on-001, a copy of it with the repo in one signed call changed so that the call no
// longer matches its binding (on-002, the check must fail it), a copy cut down to its run record (on-003), the off
// run's outcome log (off-001) and the results.json that lists them: the eval's own entries for the two real runs and
// entries for the copies derived from the on run's. recorded-on-run/ (demo-ui) holds the on run with the
// transcript's thinking and answer text deltas dropped; nothing depends on them and they are most of its size, and
// the `*_start` events give the same activity. Nothing else is edited.
//
// The script writes only those files. The expected reports and stdout files beside them are left as they are, and
// are rebuilt from `npm run verify` after the files above change, in each fixture set:
//   - expected-folder-report.json, expected-file-report.json (eval-results) and expected-verify-report.json
//     (recorded-on-run) are `JSON.stringify(report, null, 2) + "\n"`, as the tests build them, for the report of
//     verifyResultsDir (the folder) or verifyEvidence (an evidence.jsonl), the fixture's path replaced by `<fixture>`;
//   - expected-folder-stdout.txt and expected-file-stdout.txt are what `npm run verify -- <folder>` and
//     `npm run verify -- <folder>/runs/on-001/evidence.jsonl` print, the fixture's path replaced by `<fixture>`.

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [folder, onName, offName] = process.argv.slice(2);
if (folder === undefined || onName === undefined || offName === undefined) {
  console.error("usage: node eval/test/fixtures/derive.ts <results folder> <on run> <off run>");
  process.exit(2);
}
const onDir = join(folder, "runs", onName);
const offDir = join(folder, "runs", offName);
const evalResults = JSON.parse(readFileSync(join(folder, "results.json"), "utf8"));
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

const entry = (name: string) => {
  const e = evalResults.runs.find((r: { dir: string }) => r.dir === `runs/${name}`);
  if (e === undefined) throw new Error(`results.json lists no ${name}`);
  return e;
};
const onEntry = entry(onName);
const offEntry = { ...entry(offName), index: 1, dir: "runs/off-001" };
writeFileSync(
  join(results, "results.json"),
  JSON.stringify(
    {
      formatVersion: evalResults.formatVersion,
      scenario: evalResults.scenario,
      payload: evalResults.payload,
      model: evalResults.model,
      runs: [
        { ...onEntry, index: 1, dir: "runs/on-001" },
        { ...onEntry, index: 2, dir: "runs/on-002", verify: { status: "failed", problems: [] } },
        { ...onEntry, index: 3, dir: "runs/on-003", verify: { status: "not-recorded", problems: [] } },
        offEntry,
      ],
    },
    null,
    2,
  ) + "\n",
);

// demo-ui's recorded run
const rec = join(here, "../../../demo-ui/test/fixtures/recorded-on-run");
mkdirSync(rec, { recursive: true });
for (const f of ["canary.txt", "events.jsonl", "evidence.jsonl", "outcome.jsonl", "run.json"]) cpSync(join(onDir, f), join(rec, f));
const kept = lines(join(onDir, "transcript.jsonl")).filter((l) => {
  const t = JSON.parse(l).assistantMessageEvent?.type;
  return t !== "thinking_delta" && t !== "text_delta";
});
writeFileSync(join(rec, "transcript.jsonl"), kept.join("\n") + "\n");
