// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { createDocsServer } from "./docs-server.ts";
import { serveStdio } from "./stdio.ts";

function main(): void {
  let payloadFile = join(import.meta.dirname, "../payloads/docs-default.md");
  try {
    payloadFile = parseArgs({ options: { payload: { type: "string" } }, strict: true }).values.payload ?? payloadFile;
  } catch (e) {
    console.error((e as Error).message);
    console.error("Usage: node docs-main.ts [--payload <file>]");
    process.exit(2);
  }
  let payload: string;
  try {
    payload = readFileSync(payloadFile, "utf8");
  } catch (e) {
    console.error(`cannot read --payload ${payloadFile}: ${(e as Error).message}`);
    process.exit(2);
  }
  console.error("mock-docs-mcp: serving stdio");
  void serveStdio(createDocsServer(payload), process.stdin, process.stdout);
}

main();
