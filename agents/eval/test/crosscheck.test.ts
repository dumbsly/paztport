// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { setupDemo } from "../../pi-extension/test/helpers/demo.ts";
import { checkRun } from "../src/crosscheck.ts";
import { verifyEvidence } from "../src/verify.ts";
import { jsonLines, localRun, type LocalRun } from "./fixtures/local-run.ts";

const tmp = mkdtempSync(join(tmpdir(), "paztport-crosscheck-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const missing = join(tmp, "no-evidence.jsonl");
const noEvents = join(tmp, "no-events.jsonl");
const unsigned = { verdict: "REPLAY", mode: "enforce", tool: "create_branch" } as unknown as OutcomeRecord;

describe("checkRun with no signed evidence", () => {
  const base = { mode: "on" as const, evidencePath: missing, eventsPath: noEvents, report: undefined, expectedPin: "pin" };

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

let n = 0;
/** Writes JSONL lines (after editing the parsed records) to a fresh file. */
function write(lines: string[], edit?: (records: any[]) => void): string {
  const records = lines.map((l) => JSON.parse(l));
  edit?.(records);
  const path = join(tmp, `cc-${n++}.jsonl`);
  writeFileSync(path, records.map((r) => JSON.stringify(r)).join("\n") + (records.length > 0 ? "\n" : ""));
  return path;
}
const outcomes = (path: string): OutcomeRecord[] => jsonLines(path).map((l) => JSON.parse(l) as OutcomeRecord);

describe("checkRun on a phase-1 run", () => {
  it("phase1RunWithoutLocalEventsIsOk", () => {
    const run = join(import.meta.dirname, "fixtures/phase1-results/runs/on-001");
    const evidencePath = join(run, "evidence.jsonl");
    const v = checkRun({ mode: "on", outcome: "blocked", records: outcomes(join(run, "outcome.jsonl")), evidencePath, eventsPath: join(run, "events.jsonl"), report: verifyEvidence(evidencePath), expectedPin: "MGzlE8o1uqwiwIMj" });
    expect(v).toEqual({ status: "ok", problems: [] });
  });
});

describe("checkRun with local steps", { timeout: 60_000 }, () => {
  let local: LocalRun;
  let evidence: string[];
  let events: string[];
  let pin: string;
  beforeAll(async () => {
    local = await localRun(setupDemo(tmp), join(tmp, "local-run"));
    evidence = jsonLines(local.evidencePath);
    events = jsonLines(local.eventsPath);
    pin = verifyEvidence(local.evidencePath).pins[0]!;
  }, 60_000);

  const check = (o: { evidencePath?: string; eventsPath?: string; mode?: "on" | "off"; outcome?: string } = {}) => {
    const evidencePath = o.evidencePath ?? local.evidencePath;
    return checkRun({
      mode: o.mode ?? "on",
      outcome: o.outcome ?? "blocked",
      records: outcomes(local.outcomePath),
      evidencePath,
      eventsPath: o.eventsPath ?? local.eventsPath,
      report: verifyEvidence(evidencePath),
      expectedPin: pin,
    });
  };
  const localEvent = (rs: any[], id: string) => rs.find((x) => x.type === "local" && x.callId === id);
  const withoutLocal = (lines: string[], id: string) => lines.filter((l) => !(JSON.parse(l).type === "local" && JSON.parse(l).callId === id));

  it("genuineLocalRunIsOk", () => {
    expect(events.filter((l) => JSON.parse(l).type === "local")).toHaveLength(6);
    expect(check()).toEqual({ status: "ok", problems: [] });
  });

  it("anInfluenceDeniedEventWithNoEvidenceFails", () => {
    const v = check({ evidencePath: write(withoutLocal(evidence, "l_leak")) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("the events log shows local call l_leak (write) refused (INFLUENCE_DENIED), which has no verified local record in evidence.jsonl");
  });

  it("aForgedEventFails", () => {
    const forged = write(events, (rs) => rs.push({ ...localEvent(rs, "l_leak"), callId: "l_forged" }));
    expect(check({ eventsPath: forged }).problems).toContain("the events log shows local call l_forged (write) refused (INFLUENCE_DENIED), which has no verified local record in evidence.jsonl");
  });

  it("anEventWhoseVerdictDiffersFails", () => {
    const v = check({ eventsPath: write(events, (rs) => { localEvent(rs, "l_note").verdict = "INFLUENCE_DENIED"; }) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("the events log shows local call l_note refused (INFLUENCE_DENIED), but evidence.jsonl shows it allowed");
    const w = check({ eventsPath: write(events, (rs) => { localEvent(rs, "l_leak").verdict = "OK"; }) });
    expect(w.problems).toContain("the events log shows local call l_leak allowed, but evidence.jsonl shows it refused (INFLUENCE_DENIED)");
  });

  it("aLocalRecordTheEventsLogDoesNotShowFails", () => {
    // the score counts blocks from the events log, so a signed refusal it leaves out is a disagreement too
    const v = check({ eventsPath: write(withoutLocal(events, "l_leak")) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("evidence.jsonl has a local record for call l_leak (write) that the events log does not show");
  });

  it("aRepeatedEventFails", () => {
    const v = check({ eventsPath: write(events, (rs) => rs.push(structuredClone(localEvent(rs, "l_read")))) });
    expect(v.problems).toContain("the events log shows local call l_read twice");
  });

  it("eventsOutsideARunMayOnlyBeScopeRefusals", () => {
    const noRid = (verdict: string) => write(events, (rs) => rs.push({ ts: 1, type: "local", tool: "read", callId: "l_norun", verdict }));
    expect(check({ eventsPath: noRid("SCOPE_DENIED") })).toEqual({ status: "ok", problems: [] });
    const v = check({ eventsPath: noRid("INFLUENCE_DENIED") });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("the events log shows local call l_norun outside a run with verdict INFLUENCE_DENIED; outside a run the gate refuses every call as out of scope");
  });

  it("anEventsLogThatCantBeReadFails", () => {
    const path = join(tmp, `cc-${n++}.jsonl`);
    writeFileSync(path, readFileSync(local.eventsPath, "utf8") + '{"type":"local"\n');
    const v = check({ eventsPath: path });
    expect(v.status).toBe("failed");
    expect(v.problems.join(" ")).toMatch(/the events log can't be read/);
  });

  it("anOnRunWithLocalEventsAndNoEvidenceFails", () => {
    for (const outcome of ["error", "timeout", "blocked"]) {
      const v = checkRun({ mode: "on", outcome, records: [], evidencePath: missing, eventsPath: local.eventsPath, report: undefined, expectedPin: pin });
      expect(v.status, outcome).toBe("failed");
      expect(v.problems, outcome).toContain("the events log shows local tool calls during a run, but evidence.jsonl is missing, empty or has no signed records");
    }
  });

  it("anOnRunWithLocalEventsNeedsTheClientRecord", () => {
    // a run with Paztport on is in enforce mode, which always writes the client record
    const v = check({ evidencePath: write(evidence.filter((l) => !["client", "local"].includes(JSON.parse(l).type))) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("the events log shows local tool calls during a run, but evidence.jsonl has no client record");
  });
});
