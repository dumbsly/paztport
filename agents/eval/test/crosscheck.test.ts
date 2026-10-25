// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { OutcomeRecord } from "../../mock-github-mcp/src/outcome.ts";
import { setupDemo } from "../../pi-extension/test/helpers/demo.ts";
import { checkRun, reusedLocalSignatures } from "../src/crosscheck.ts";
import { recheckResultsDir } from "../src/recheck.ts";
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
  let other: LocalRun; // a second run with the same keys, as two runs of one eval have
  let evidence: string[];
  let events: string[];
  let pin: string;
  beforeAll(async () => {
    const demo = setupDemo(tmp);
    local = await localRun(demo, join(tmp, "local-run"));
    other = await localRun(demo, join(tmp, "other-run"));
    evidence = jsonLines(local.evidencePath);
    events = jsonLines(local.eventsPath);
    pin = verifyEvidence(local.evidencePath).pins[0]!;
  }, 60_000);

  const check = (o: { evidencePath?: string; eventsPath?: string; mode?: "on" | "off"; outcome?: string; localTools?: boolean; outcomePath?: string } = {}) => {
    const evidencePath = o.evidencePath ?? local.evidencePath;
    return checkRun({
      mode: o.mode ?? "on",
      outcome: o.outcome ?? "blocked",
      localTools: o.localTools ?? true,
      records: outcomes(o.outcomePath ?? local.outcomePath),
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

  it("anEventWhoseToolDiffersFails", () => {
    const v = check({ eventsPath: write(events, (rs) => { localEvent(rs, "l_note").tool = "read"; }) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("the events log shows local call l_note as read, but evidence.jsonl shows write");
  });

  it("reviewProbesFail", () => {
    // an allowed write turned into a signed-looking unlisted-route refusal, events edited to match
    const downgrade = check({
      evidencePath: write(evidence, (rs) => { const x = localEvent(rs, "l_note"); x.proof = null; x.verdict = "PATH_NOT_ALLOWED"; }),
      eventsPath: write(events, (rs) => { localEvent(rs, "l_note").verdict = "PATH_NOT_ALLOWED"; }),
    });
    expect(downgrade.status).toBe("failed");
    // the rules removed and every step turned into a scope refusal, events edited to match
    const nullRules = check({
      evidencePath: write(evidence, (rs) => {
        const c = rs.find((x) => x.type === "client");
        c.rules = null;
        c.rulesProof = null;
        for (const x of rs) if (x.type === "local") x.verdict = "SCOPE_DENIED";
      }),
      eventsPath: write(events, (rs) => { for (const x of rs) if (x.type === "local") x.verdict = "SCOPE_DENIED"; }),
    });
    expect(nullRules.status).toBe("failed");
  });

  it("aLocalStepCopiedFromAnotherRunFails", () => {
    // review probe: another run's signed refusal (with its run record) moved into this run's evidence and events
    const P = (path: string) => jsonLines(path).map((l) => JSON.parse(l));
    const theirs = P(other.evidencePath);
    const leak = theirs.find((x) => x.type === "local" && x.callId === "l_leak");
    const ev = write(withoutLocal(evidence, "l_leak"), (rs) => rs.push(theirs.find((x) => x.type === "run"), leak));
    const evt = write(withoutLocal(events, "l_leak"), (rs) => rs.push(P(other.eventsPath).find((x) => x.type === "local" && x.callId === "l_leak")));
    expect(verifyEvidence(ev).ok).toBe(true); // each record is genuine
    const v = check({ evidencePath: ev, eventsPath: evt });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("evidence.jsonl has a local record for call l_leak in a run the server never saw");
  });

  it("aLocalSignatureInTwoRunsIsReported", () => {
    const copy = join(tmp, "copy-run");
    const theirs = jsonLines(other.evidencePath);
    const leak = theirs.find((l) => JSON.parse(l).type === "local" && JSON.parse(l).callId === "l_leak")!;
    const mixed = write([leak]); // a run whose only local step is run b's
    const found = reusedLocalSignatures(new Map([["runs/a", local.evidencePath], ["runs/b", other.evidencePath], [copy, mixed]]));
    expect(found.get("runs/a")).toBeUndefined();
    expect(found.get("runs/b")).toEqual([`a signed local step in evidence.jsonl also appears in ${copy}'s evidence`]);
    expect(found.get(copy)).toEqual(["a signed local step in evidence.jsonl also appears in runs/b's evidence"]);
    // a missing or unreadable file has nothing to compare
    expect(reusedLocalSignatures(new Map([["runs/a", local.evidencePath], ["runs/x", join(tmp, "nope.jsonl")]])).size).toBe(0);
  });

  it("recheckFailsBothRunsThatShareALocalStep", () => {
    // a results folder whose second run is a copy of the first: each file is genuine on its own
    const dir = join(tmp, "copied-folder");
    for (const name of ["on-001", "on-002"]) {
      mkdirSync(join(dir, "runs", name), { recursive: true });
      for (const f of ["evidence.jsonl", "events.jsonl", "outcome.jsonl"]) copyFileSync(join(local.runDir, f), join(dir, "runs", name, f));
    }
    const runs = ["on-001", "on-002"].map((name, i) => ({ mode: "on", index: i + 1, dir: `runs/${name}`, outcome: "blocked", status: "completed" }));
    const rc = recheckResultsDir(dir, { formatVersion: 1, runs, serverKey: { fingerprint: pin } });
    expect(rc.runs.map((r) => r.verify!.status)).toEqual(["failed", "failed"]);
    expect(rc.runs[0]!.verify!.problems).toContain("a signed local step in evidence.jsonl also appears in runs/on-002's evidence");
    expect(rc.runs[1]!.verify!.problems).toContain("a signed local step in evidence.jsonl also appears in runs/on-001's evidence");
  });

  it("aLocalToolsRunNeedsAClientRecordWithRules", () => {
    const noRules = write(evidence, (rs) => { const c = rs.find((x) => x.type === "client"); c.rules = null; c.rulesProof = null; });
    const v = check({ evidencePath: write(jsonLines(noRules).filter((l) => JSON.parse(l).type !== "local")), eventsPath: write([]) });
    expect(v.status).toBe("failed");
    expect(v.problems).toContain("a local-tools run with Paztport on, but evidence.jsonl has no verified client record with local rules");
    const none = check({ evidencePath: write(evidence.filter((l) => !["client", "local"].includes(JSON.parse(l).type))), eventsPath: write([]) });
    expect(none.problems).toContain("a local-tools run with Paztport on, but evidence.jsonl has no verified client record with local rules");
    // an MCP-only scenario has no such need
    expect(check({ evidencePath: write(evidence.filter((l) => !["client", "local"].includes(JSON.parse(l).type))), eventsPath: write([]), localTools: false }).status).toBe("ok");
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
