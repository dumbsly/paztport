// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { checkRun } from "../src/crosscheck.ts";

const tmp = mkdtempSync(join(tmpdir(), "paztport-crosscheck-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const missing = join(tmp, "no-evidence.jsonl");
const unsigned = { verdict: "REPLAY", mode: "enforce", tool: "create_branch" } as unknown as OutcomeRecord;

describe("checkRun with no signed evidence", () => {
  const base = { mode: "on" as const, evidencePath: missing, report: undefined, expectedPin: "pin" };

  it("an on-run that ended in error with a usable log and no signed calls is not-recorded", () => {
    expect(checkRun({ ...base, outcome: "error", records: [] }).status).toBe("not-recorded");
    expect(checkRun({ ...base, outcome: "error", records: [unsigned] }).status).toBe("not-recorded");
  });

  it("an on-run whose outcome log could not be used is failed, never not-recorded", () => {
    const v = checkRun({ ...base, outcome: "error", records: null });
    expect(v.status).toBe("failed");
    expect(v.problems.join(" ")).toMatch(/outcome log could not be used/);
  });

  it("an on-run that timed out before any session is not-recorded, not a failed check", () => {
    expect(checkRun({ ...base, outcome: "timeout", records: [] })).toEqual({ status: "not-recorded", problems: [] });
    expect(checkRun({ ...base, outcome: "timeout", records: null }).status).toBe("failed");
  });

  it("an on-run that finished with no evidence still fails", () => {
    expect(checkRun({ ...base, outcome: "resisted", records: [] }).status).toBe("failed");
  });

  it("an off run with nothing signed is none", () => {
    expect(checkRun({ ...base, mode: "off", outcome: "error", records: null }).status).toBe("none");
  });
});
