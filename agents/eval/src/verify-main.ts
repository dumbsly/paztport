// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Usage: node eval/src/verify-main.ts <results-dir | evidence.jsonl>
// Exit code: 0 if no file failed, 1 if any did, 2 on a usage error. A file with no signed records (only the
// unsigned run record: Paztport was off, or the run ended before a session) is reported as NOTHING TO CHECK,
// which is neither a pass nor a failure.

import { statSync } from "node:fs";
import { NOT_FAILURES, verifyEvidence, verifyResultsDir, type VerifyReport } from "./verify.ts";

function line(r: VerifyReport): string {
  if (r.nothingToCheck) return `NOTHING TO CHECK ${r.file} (no signed records: Paztport was off, or the run ended before a session)`;
  const pin = r.pins.length > 0 ? ` pin ${r.pins.join(",")}` : "";
  if (r.ok) {
    const refused = r.items.filter((i) => i.result === "REFUSED").length;
    // A server refusal carries no signature, so verify reports it as it is found and says so.
    const note = refused > 0 ? `, ${refused} REFUSED (server refusal; refusals are not signed)` : "";
    return `OK  ${r.file} (${r.items.length} items${note})${pin}`;
  }
  const first = r.items.find((i) => !NOT_FAILURES.includes(i.result))!;
  const where = first.line > 0 ? `line ${first.line} ` : "";
  const id = first.callId !== undefined ? ` ${first.callId}` : "";
  return `FAIL ${r.file} ${where}${first.type}${id}: ${first.result}${pin}`;
}

const args = process.argv.slice(2);
if (args.length !== 1 || args[0]!.startsWith("-")) {
  process.stderr.write("usage: verify <results-dir | evidence.jsonl>\n");
  process.exit(2);
}
const target = args[0]!;
let reports: VerifyReport[];
try {
  reports = statSync(target).isDirectory() ? verifyResultsDir(target) : [verifyEvidence(target)];
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
