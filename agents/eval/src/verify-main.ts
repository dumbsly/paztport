// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Usage: node eval/src/verify-main.ts <results-dir | evidence.jsonl>
// Exit code: 0 if every file verifies, 1 if any does not, 2 on a usage error.

import { statSync } from "node:fs";
import { verifyEvidence, verifyResultsDir, type VerifyReport } from "./verify.ts";

const NOT_FAILURES: readonly string[] = ["OK", "REFUSED", "NO_RESPONSE"];

function line(r: VerifyReport): string {
  if (r.ok) {
    return `OK  ${r.file} (${r.items.length} items)`;
  }
  const first = r.items.find((i) => !NOT_FAILURES.includes(i.result))!;
  const where = first.line > 0 ? `line ${first.line} ` : "";
  const id = first.callId !== undefined ? ` ${first.callId}` : "";
  return `FAIL ${r.file} ${where}${first.type}${id}: ${first.result}`;
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
