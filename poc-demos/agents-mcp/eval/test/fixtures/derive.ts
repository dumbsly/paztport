// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds the two fixture sets from one results folder of the scripted run (record.ts): the real eval, pi, extension
// and mock server with a stub in place of the model, run with `--modes on,off --runs 1`, a Paztport-on run that the
// server blocked and a Paztport-off run.
//
// eval-results/ holds the on run as on-001, a copy of it with the repo in one signed call changed so that the call no
// longer matches its binding (on-002, the check must fail it), a copy cut down to its run record (on-003), the off
// run's outcome log (off-001) and the results.json that lists them: the eval's own entries for the two real runs and
// entries for the copies derived from the on run's. recorded-on-run/ (demo-ui) holds the on run with the
// transcript's thinking and answer text deltas dropped; nothing depends on them, and the `*_start` events give the
// same activity. Every evidence record is copied as the extension wrote it; only on-002's one call is edited.
//
// It writes only those files. The expected reports and stdout files beside them are rebuilt by record.ts.

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const EVAL_RESULTS = join(import.meta.dirname, "eval-results");
const RECORDED_ON_RUN = join(import.meta.dirname, "../../../demo-ui/test/fixtures/recorded-on-run");

const lines = (file: string): string[] => readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");

/** Writes eval-results/ and demo-ui's recorded-on-run/ from two runs of `resultsDir`, named as on-001 and off-001 are. */
export function derive(resultsDir: string, onRun: string, offRun: string): void {
  const onDir = join(resultsDir, "runs", onRun);
  const offDir = join(resultsDir, "runs", offRun);
  const evalResults = JSON.parse(readFileSync(join(resultsDir, "results.json"), "utf8"));

  // eval-results
  rmSync(join(EVAL_RESULTS, "runs"), { recursive: true, force: true });
  const on1 = join(EVAL_RESULTS, "runs/on-001");
  mkdirSync(on1, { recursive: true });
  for (const f of ["events.jsonl", "evidence.jsonl", "outcome.jsonl"]) cpSync(join(onDir, f), join(on1, f));
  const evidence = lines(join(onDir, "evidence.jsonl"));

  let tampered = false;
  const changed = evidence.map((l) => {
    const rec = JSON.parse(l);
    if (tampered || rec.type !== "call" || rec.params?.arguments?.repo !== "payroll-notes") return l;
    rec.params.arguments.repo = "website";
    tampered = true;
    return JSON.stringify(rec);
  });
  if (!tampered) throw new Error("no call on payroll-notes in the on run's evidence");
  mkdirSync(join(EVAL_RESULTS, "runs/on-002"), { recursive: true });
  writeFileSync(join(EVAL_RESULTS, "runs/on-002/evidence.jsonl"), changed.join("\n") + "\n");

  const runRecord = evidence.filter((l) => JSON.parse(l).type === "run");
  if (runRecord.length !== 1) throw new Error("expected one run record in the on run's evidence");
  mkdirSync(join(EVAL_RESULTS, "runs/on-003"), { recursive: true });
  writeFileSync(join(EVAL_RESULTS, "runs/on-003/evidence.jsonl"), runRecord[0] + "\n");

  mkdirSync(join(EVAL_RESULTS, "runs/off-001"), { recursive: true });
  cpSync(join(offDir, "outcome.jsonl"), join(EVAL_RESULTS, "runs/off-001/outcome.jsonl"));

  const entry = (name: string) => {
    const e = evalResults.runs.find((r: { dir: string }) => r.dir === `runs/${name}`);
    if (e === undefined) throw new Error(`results.json lists no ${name}`);
    return e;
  };
  const onEntry = entry(onRun);
  const offEntry = { ...entry(offRun), index: 1, dir: "runs/off-001" };
  writeFileSync(
    join(EVAL_RESULTS, "results.json"),
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
  mkdirSync(RECORDED_ON_RUN, { recursive: true });
  for (const f of ["canary.txt", "events.jsonl", "evidence.jsonl", "outcome.jsonl", "run.json"]) cpSync(join(onDir, f), join(RECORDED_ON_RUN, f));
  const kept = lines(join(onDir, "transcript.jsonl")).filter((l) => {
    const t = JSON.parse(l).assistantMessageEvent?.type;
    return t !== "thinking_delta" && t !== "text_delta";
  });
  writeFileSync(join(RECORDED_ON_RUN, "transcript.jsonl"), kept.join("\n") + "\n");
}
