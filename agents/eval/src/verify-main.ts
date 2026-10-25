// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Usage: node eval/src/verify-main.ts <results-dir | demo single-run folder | evidence.jsonl>
// Exit code: 0 if no file failed, 1 if any did, 2 on a usage error. A file with no signed records (only the
// unsigned run record, and the client record written at session start: the run ended before a session, or
// the signed records were cut away) is reported as
// NOTHING TO CHECK, which is neither a pass nor a failure. Runs with Paztport off write no evidence file at
// all. On its own a single file can't tell an on-run cut down to its run record from a run that ended before
// a session; a results folder with its results.json can, because it says which runs had Paztport on and
// whether their evidence was checked (see verifyResultsDir). In folder mode verify also
// reads each run's outcome log and events log: a run whose outcome log shows signed calls, or whose events
// log shows local tool calls made during a run, must have signed evidence, whatever results.json says, and
// a log that exists but can't be read fails. It does not compare each evidence record with the logs or
// re-score the run. Local refusals are signed, unlike the server's, and the output says which is which.
//
// A demo single-run folder (demo-run.json and the run's files at the top, no runs/ folder) is checked as the
// eval checks each of its runs: its evidence.jsonl is verified, then one more line says whether the events log,
// the outcome log and the evidence agree, and whether the evidence is pinned to the server key demo-run.json
// records. An older demo-run.json records no server key; the pins are then not compared, and a line says so.

import { statSync } from "node:fs";
import { isSingleRunDir, verifySingleRunDir } from "./crosscheck.ts";
import { NOT_FAILURES, verifyEvidence, verifyResultsDir, type VerifyReport } from "./verify.ts";

function line(r: VerifyReport): string {
  if (r.problem !== undefined) return `FAIL ${r.file}: ${r.problem}`;
  if (r.nothingToCheck) return `NOTHING TO CHECK ${r.file} (no signed records: Paztport was off, or the run ended before a session)`;
  const pin = r.pins.length > 0 ? ` pin ${r.pins.join(",")}` : "";
  if (r.ok) {
    const refused = r.items.filter((i) => i.result === "REFUSED" && i.type !== "local").length;
    const local = r.items.filter((i) => i.result === "REFUSED" && i.type === "local").length;
    // A server refusal carries no signature, so verify reports it as it is found and says so. A local
    // refusal is signed by the client and its verdict re-derived from the signed rules, so it says that.
    const server = refused === 0 ? "" : `, ${refused} REFUSED (server refusal; ${local > 0 ? "not signed" : "refusals are not signed"})`;
    const note = server + (local > 0 ? `, ${local} REFUSED (local refusal; signed)` : "");
    return `OK  ${r.file} (${r.items.length} items${note})${pin}`;
  }
  const first = r.items.find((i) => !NOT_FAILURES.includes(i.result))!;
  const where = first.line > 0 ? `line ${first.line} ` : "";
  const id = first.callId !== undefined ? ` ${first.callId}` : "";
  return `FAIL ${r.file} ${where}${first.type}${id}: ${first.result}${pin}`;
}

const args = process.argv.slice(2);
if (args.length !== 1 || args[0]!.startsWith("-")) {
  process.stderr.write("usage: verify <results-dir | run folder | evidence.jsonl>\n");
  process.exit(2);
}
const target = args[0]!;
let isDir = false;
try {
  isDir = statSync(target).isDirectory();
} catch {
  // a missing path is reported as an unreadable file below
}
if (isDir && isSingleRunDir(target)) {
  const { report, crossCheck, noServerKey } = verifySingleRunDir(target);
  process.stdout.write(line(report) + "\n");
  if (noServerKey) process.stdout.write("NOTE demo-run.json records no server key fingerprint (an older run), so the evidence pin was not compared with it\n");
  const cross =
    crossCheck.status === "ok"
      ? "OK  cross-check (events, outcome log and evidence agree)"
      : crossCheck.status === "failed"
        ? `FAIL cross-check: ${crossCheck.problems.join("; ")}`
        : crossCheck.status === "none"
          ? "NOTHING TO CHECK cross-check (Paztport was off)"
          : "NOTHING TO CHECK cross-check (Paztport was on, but the run ended before anything was recorded)";
  process.stdout.write(cross + "\n");
  process.exit(report.ok && crossCheck.status !== "failed" ? 0 : 1);
}
let reports: VerifyReport[];
try {
  reports = isDir ? verifyResultsDir(target) : [verifyEvidence(target)];
} catch {
  reports = [verifyEvidence(target)]; // a missing path is reported as an unreadable file
}
if (reports.length === 0) {
  process.stdout.write(`FAIL ${target}: no runs/*/evidence.jsonl found\n`);
  process.exit(1);
}
for (const r of reports) {
  process.stdout.write(line(r) + "\n");
}
process.exit(reports.every((r) => r.ok) ? 0 : 1);
