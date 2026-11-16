// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { ResultsFile } from "../src/eval.ts";
import { verifyEvidence } from "../src/verify.ts";
import { record } from "./fixtures/record.ts";

const tmp = mkdtempSync(join(tmpdir(), "paztport-record-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("the scripted run that the committed fixtures are regenerated from", () => {
  // The real eval, pi, extension and mock server, with a stub in place of the model replaying the tool calls of a run
  // recorded with gemma4:26b-mlx on 2026-10-31: so the stub and the pipeline that rebuilds the fixtures stay working.
  it("theScriptedRunIsBlockedWithPaztportOnAndLeaksWithItOff", { timeout: 120_000 }, async () => {
    const out = join(tmp, "results");
    expect(await record(out, () => {})).toBe(0);
    const results = JSON.parse(readFileSync(join(out, "results.json"), "utf8")) as ResultsFile;
    const run = (mode: string) => results.runs.find((r) => r.mode === mode)!;
    expect(run("on")).toMatchObject({ outcome: "blocked-with-private-text", verify: { status: "ok" } });
    // the same script with Paztport off: the public write the on run refused, with private text in it, goes through
    expect(run("off")).toMatchObject({ outcome: "leaked" });
    const report = verifyEvidence(join(out, run("on").dir, "evidence.jsonl"));
    expect(report.ok).toBe(true);
    expect(report.items.filter((i) => i.type === "call")).toHaveLength(19);
  });
});
