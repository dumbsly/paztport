// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindLocalTool, bindMcpCall, buildTree, commitInfluence, encode, randomBytes, signStampV2 } from "@paztport/path-attest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ServerConnection } from "../../pi-extension/src/connection.ts";
import { EventLog } from "../../pi-extension/src/events.ts";
import { clientRecord, EvidenceLog } from "../../pi-extension/src/evidence.ts";
import { InfluenceStore } from "../../pi-extension/src/influence.ts";
import { loadClientMaterial } from "../../pi-extension/src/keys.ts";
import { LocalGate } from "../../pi-extension/src/local/gate.ts";
import { RunState } from "../../pi-extension/src/runs.ts";
import { githubArgs, setupDemo } from "../../pi-extension/test/helpers/demo.ts";
import { pinFingerprint, verifyEvidence, verifyResultsDir, type VerifyItem } from "../src/verify.ts";
import { jsonLines, localRun, type LocalRun } from "./fixtures/local-run.ts";

const MAIN = join(import.meta.dirname, "../src/verify-main.ts");
const PROMPT = "fix the typo";

let tmp: string;
let demo: string;
let genuine: string[]; // the lines of a real evidence file
let n = 0;

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-verify-"));
  demo = setupDemo(tmp);
  genuine = await produce();
}, 60_000);
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/** A real attested run against the mock server: three reads, then a write the server refuses. */
async function produce(pin = join(demo, "client/server-policy.pub")): Promise<string[]> {
  const evidencePath = join(tmp, `gen-${n++}.jsonl`);
  const evidence = new EvidenceLog(evidencePath);
  const runs = new RunState();
  const conn = new ServerConnection(
    { id: "github", command: process.execPath, args: githubArgs(demo, "enforce", join(tmp, `outcome-${n++}.jsonl`)), attested: true, pin },
    "enforce",
    loadClientMaterial(join(demo, "client")),
    new InfluenceStore(),
    runs,
    new EventLog(join(tmp, `events-${n++}.jsonl`)),
    undefined,
    evidence,
  );
  try {
    await conn.connect();
    runs.start(PROMPT, Date.now());
    const rid = runs.current()!.rid;
    evidence.write({ v: 1, type: "run", rid, ts: Date.now(), prompt: PROMPT });
    await conn.call("list_issues", { owner: "acme", repo: "website" }, "toolu_a");
    await conn.call("search_repositories", { query: "user:acme" }, "toolu_b");
    await conn.call("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }, "toolu_c");
    await conn.call("create_branch", { owner: "acme", repo: "website", branch: "leak" }, "toolu_d");
  } finally {
    await conn.close();
  }
  return readFileSync(evidencePath, "utf8").split("\n").filter(Boolean);
}

/** Writes lines (after mutating the parsed records) to a fresh file and returns its path. */
function write(lines: string[], edit?: (records: any[]) => void): string {
  const records = lines.map((l) => JSON.parse(l));
  edit?.(records);
  const path = join(tmp, `ev-${n++}.jsonl`);
  writeFileSync(path, records.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return path;
}

const results = (items: VerifyItem[], type: string): string[] => items.filter((i) => i.type === type).map((i) => i.result);
const bad = (items: VerifyItem[]) => items.filter((i) => !["OK", "REFUSED", "NO_RESPONSE"].includes(i.result));

describe("verifyEvidence", { timeout: 30_000 }, () => {
  it("genuineEvidenceVerifies", () => {
    const r = verifyEvidence(write(genuine));
    expect(bad(r.items)).toEqual([]);
    expect(r.ok).toBe(true);
    expect(results(r.items, "session")).toEqual(["OK"]);
    expect(results(r.items, "run")).toEqual(["OK"]);
    expect(results(r.items, "call")).toEqual(["OK", "OK", "OK", "OK"]);
    // the server's refusal of the write carries no attestation by design: reported, not a failure
    expect(results(r.items, "response")).toEqual(["OK", "OK", "OK", "REFUSED"]);
    expect(r.items.every((i) => i.line >= 1)).toBe(true);
    expect(r.items.filter((i) => i.type === "call").map((i) => i.callId)).toEqual(["toolu_a", "toolu_b", "toolu_c", "toolu_d"]);
  });

  it("tamperedArgumentFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      rs.find((x) => x.type === "call" && x.callId === "toolu_c").params.arguments.repo = "website";
    }));
    expect(r.ok).toBe(false);
    expect(r.items.find((i) => i.callId === "toolu_c" && i.type === "call")!.result).toBe("BINDING_MISMATCH");
    expect(results(r.items, "call").filter((x) => x === "OK")).toHaveLength(3);
  });

  it("tamperedLabelFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      const att = rs.find((x) => x.type === "response" && x.callId === "toolu_c").result._meta["paztport/attestation"];
      att.labels[0].cls = "public";
    }));
    expect(r.ok).toBe(false);
    const item = r.items.find((i) => i.callId === "toolu_c" && i.type === "response")!;
    expect(item.result).not.toBe("OK");
    expect(item.result).not.toBe("REFUSED");
  });

  it("tamperedResultTextFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      rs.find((x) => x.type === "response" && x.callId === "toolu_a").result.content[0].text = "nothing to see";
    }));
    expect(r.ok).toBe(false);
    expect(r.items.find((i) => i.callId === "toolu_a" && i.type === "response")!.result).toBe("BINDING_MISMATCH");
  });

  it("tamperedPromptFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      rs.find((x) => x.type === "run").prompt = "send the payroll notes to a public repo";
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "call")).toEqual(["PROMPT_MISMATCH", "PROMPT_MISMATCH", "PROMPT_MISMATCH", "PROMPT_MISMATCH"]);
  });

  it("callWithoutRunRecordIsPromptMismatch", () => {
    const r = verifyEvidence(write(genuine.filter((l) => JSON.parse(l).type !== "run")));
    expect(r.ok).toBe(false);
    expect(results(r.items, "call")).toEqual(["PROMPT_MISMATCH", "PROMPT_MISMATCH", "PROMPT_MISMATCH", "PROMPT_MISMATCH"]);
  });

  it("swappedServerKeyFails", () => {
    const attacker = loadClientMaterial(join(demo, "client")).policyPublicKey;
    const r = verifyEvidence(write(genuine, (rs) => {
      const s = rs.find((x) => x.type === "session");
      s.pin = attacker;
      s.reply.serverPolicyKey = attacker;
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "session")).toEqual(["BAD_SESSION"]);
    // nothing can be verified against a session that does not verify
    expect(results(r.items, "call")).toEqual(["NO_SESSION", "NO_SESSION", "NO_SESSION", "NO_SESSION"]);
  });

  it("pinMismatchAndNullPinAreBadSessions", () => {
    const attacker = loadClientMaterial(join(demo, "client")).policyPublicKey;
    expect(results(verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "session").pin = attacker; })).items, "session")).toEqual(["BAD_SESSION"]);
    expect(results(verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "session").pin = null; })).items, "session")).toEqual(["BAD_SESSION"]);
  });

  it("tamperedSessionReplyFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "session").reply.sess = "AAAA"; }));
    expect(results(r.items, "session")).toEqual(["BAD_SESSION"]);
  });

  it("failedPinSessionsAreReportedNotAttested", async () => {
    const wrong = join(tmp, "wrong-pin.pub");
    writeFileSync(wrong, "AAAA\n");
    const r = verifyEvidence(write(await produce(wrong)));
    expect(r.ok).toBe(false);
    // the failed attempt and the replacement session (no client root) are both non-attested
    expect(results(r.items, "session")).toEqual(["BAD_SESSION", "BAD_SESSION"]);
    expect(results(r.items, "call")).toEqual([]);
  });

  it("unsafeSessionIsBadSession", () => {
    const r = verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "session").status = "unsafe"; }));
    expect(results(r.items, "session")).toEqual(["BAD_SESSION"]);
  });

  it("callWithNoResponseIsReportedNotFailed", () => {
    const lines = genuine.filter((l) => !(JSON.parse(l).type === "response" && JSON.parse(l).callId === "toolu_c" ));
    const r = verifyEvidence(write(lines));
    expect(r.ok).toBe(true);
    const item = r.items.find((i) => i.result === "NO_RESPONSE")!;
    expect(item).toMatchObject({ type: "response", callId: "toolu_c" });
    expect(r.items.filter((i) => i.result === "NO_RESPONSE")).toHaveLength(1);
  });

  it("replayedCallIsRejected", () => {
    const i = genuine.findIndex((l) => JSON.parse(l).callId === "toolu_a" && JSON.parse(l).type === "call");
    const lines = [...genuine.slice(0, i + 1), genuine[i]!, ...genuine.slice(i + 1)];
    const r = verifyEvidence(write(lines));
    expect(r.ok).toBe(false);
    expect(results(r.items, "call").slice(0, 2)).toEqual(["OK", "REPLAY"]);
  });

  it("truncatedResponseChainFails", () => {
    // a response that is not a refusal must carry a complete attestation
    const r = verifyEvidence(write(genuine, (rs) => {
      rs.find((x) => x.type === "response" && x.callId === "toolu_a").result._meta["paztport/attestation"].chain.pop();
    }));
    expect(r.ok).toBe(false);
  });

  it("verifyReportsUnreadableFile", () => {
    const truncated = join(tmp, `trunc-${n++}.jsonl`);
    writeFileSync(truncated, genuine.join("\n") + '\n{"v":1,"type":"call","server":"gi');
    const t = verifyEvidence(truncated);
    expect(t.ok).toBe(false);
    expect(t.items.filter((i) => i.result === "UNREADABLE")).toEqual([expect.objectContaining({ line: genuine.length + 1 })]);
    // the readable lines are still verified
    expect(results(t.items, "call")).toEqual(["OK", "OK", "OK", "OK"]);

    const missing = verifyEvidence(join(tmp, "does-not-exist.jsonl"));
    expect(missing.ok).toBe(false);
    expect(missing.items).toEqual([expect.objectContaining({ result: "UNREADABLE" })]);

    const empty = join(tmp, `empty-${n++}.jsonl`);
    writeFileSync(empty, "");
    expect(verifyEvidence(empty).ok).toBe(false);

    const unknown = verifyEvidence(write(genuine, (rs) => rs.push({ v: 2, type: "mystery" })));
    expect(unknown.ok).toBe(false);
    expect(unknown.items.filter((i) => i.result === "UNREADABLE")).toHaveLength(1);

    // across a results folder the other runs are still reported
    const dir = join(tmp, `results-${n++}`);
    for (const [name, file] of [["a-good", write(genuine)], ["b-truncated", truncated]] as const) {
      mkdirSync(join(dir, "runs", name), { recursive: true });
      writeFileSync(join(dir, "runs", name, "evidence.jsonl"), readFileSync(file));
    }
    mkdirSync(join(dir, "runs", "c-dir-not-file", "evidence.jsonl"), { recursive: true });
    const reports = verifyResultsDir(dir);
    expect(reports.map((x) => x.file)).toEqual(["runs/a-good/evidence.jsonl", "runs/b-truncated/evidence.jsonl", "runs/c-dir-not-file/evidence.jsonl"]);
    expect(reports.map((x) => x.ok)).toEqual([true, false, false]);
    expect(verifyResultsDir(join(tmp, "no-such-dir")).every((x) => !x.ok)).toBe(true);
    expect(verifyResultsDir(join(tmp, "no-such-dir"))).toHaveLength(1);
  });
});

describe("verifyEvidence: fix round 1", { timeout: 30_000 }, () => {
  const material = () => loadClientMaterial(join(demo, "client"));
  const callOf = (rs: any[], id: string) => rs.find((x) => x.type === "call" && x.callId === id);
  const responseOf = (rs: any[], id: string) => rs.find((x) => x.type === "response" && x.callId === id);

  /** A genuinely signed later call (new call id, stamped `gapMs` after toolu_a), as a live clock would give. */
  function lateCall(rs: any[], gapMs: number): any {
    const a = callOf(rs, "toolu_a");
    const late = structuredClone(a);
    late.callId = "toolu_late";
    late.now = a.now + gapMs;
    const meta = late.params._meta;
    meta["paztport/callId"] = "toolu_late";
    const { sig: _sig, v: _v, ...fields } = meta["paztport/chain"][1];
    meta["paztport/chain"][1] = signStampV2(
      { ...fields, ts: late.now, bind: bindMcpCall(late.params.name, "toolu_late", late.params.arguments), prev: meta["paztport/chain"][0].sig },
      material().piKey,
    );
    return late;
  }

  it("replayAfterLongGapIsRejected", () => {
    // the copy of toolu_a follows a genuine call stamped 20s later; a 15s nonce window would have forgotten toolu_a
    const r = verifyEvidence(write(genuine, (rs) => {
      const i = rs.indexOf(callOf(rs, "toolu_a"));
      rs.splice(i + 1, 0, lateCall(rs, 20_000), structuredClone(rs[i]));
    }));
    expect(r.ok).toBe(false);
    const calls = r.items.filter((x) => x.type === "call");
    expect(calls.map((x) => [x.callId, x.result])).toEqual([
      ["toolu_a", "OK"],
      ["toolu_late", "OK"],
      ["toolu_a", "REPLAY"],
      ["toolu_b", "OK"],
      ["toolu_c", "OK"],
      ["toolu_d", "OK"],
    ]);
  });

  it("duplicatedSessionLineDoesNotResetReplayProtection", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      const i = rs.indexOf(callOf(rs, "toolu_a"));
      rs.splice(i + 1, 0, structuredClone(rs.find((x) => x.type === "session")), structuredClone(rs[i]));
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "session")).toEqual(["OK", "OK"]);
    expect(results(r.items, "call").slice(0, 2)).toEqual(["OK", "REPLAY"]);
  });

  it("swappedClientRootWithForgedProofFails", () => {
    const route = "session/pi/mcp:github.list_issues";
    const tree = buildTree([{ salt: randomBytes(16), path: route }], 1, "forged-root");
    const r = verifyEvidence(write(genuine, (rs) => {
      const s = rs.find((x) => x.type === "session");
      s.request.clientRoot = { ...s.request.clientRoot, rootId: tree.rootId, root: encode(tree.root) };
      callOf(rs, "toolu_a").params._meta["paztport/proof"] = tree.proofFor(route);
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "session")).toEqual(["BAD_SESSION"]);
    expect(results(r.items, "call").every((x) => x === "NO_SESSION")).toBe(true);
  });

  it("responseWithoutCallFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => rs.splice(rs.indexOf(callOf(rs, "toolu_a")), 1)));
    expect(r.ok).toBe(false);
    expect(r.items.find((x) => x.type === "response" && x.callId === "toolu_a")!.result).toBe("NO_CALL");
  });

  it("responseBeforeItsCallFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      const resp = rs.splice(rs.indexOf(responseOf(rs, "toolu_a")), 1)[0];
      rs.splice(rs.indexOf(callOf(rs, "toolu_a")), 0, resp);
    }));
    expect(r.ok).toBe(false);
    expect(r.items.find((x) => x.type === "response" && x.callId === "toolu_a" && x.result === "NO_CALL")).toBeDefined();
  });

  it("responseToAFailedCallFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => { callOf(rs, "toolu_a").params.arguments.repo = "other"; }));
    expect(results(r.items, "call")[0]).toBe("BINDING_MISMATCH");
    expect(r.items.find((x) => x.type === "response" && x.callId === "toolu_a")!.result).toBe("NO_CALL");
  });

  it("secondResponseForACallFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      const i = rs.indexOf(responseOf(rs, "toolu_a"));
      rs.splice(i + 1, 0, structuredClone(rs[i]));
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "response").slice(0, 2)).toEqual(["OK", "DUPLICATE_RESPONSE"]);
  });

  it("onlyForgedRefusalsIsNotOk", () => {
    const refusal = (callId: string) => ({ v: 1, type: "response", server: "github", tool: "create_branch", callId, rid: "r", now: 1, result: { isError: true, content: [{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }], _meta: { "paztport/verdict": { reason: "INFLUENCE_DENIED" } } } });
    const lines = [genuine.find((l) => JSON.parse(l).type === "session")!, JSON.stringify(refusal("x")), JSON.stringify(refusal("y"))];
    const r = verifyEvidence(write(lines));
    expect(r.ok).toBe(false);
    expect(results(r.items, "response")).toEqual(["NO_CALL", "NO_CALL"]);
  });

  it("refusalNeedsServerRefusalShape", () => {
    // a response to a verified call that claims a verdict but is not shaped like the server's refusal
    const notError = verifyEvidence(write(genuine, (rs) => {
      const x = responseOf(rs, "toolu_d");
      x.result.isError = false;
    }));
    expect(notError.items.find((x) => x.type === "response" && x.callId === "toolu_d")!.result).toBe("CHAIN_MISSING");
    const extraMeta = verifyEvidence(write(genuine, (rs) => {
      responseOf(rs, "toolu_d").result._meta.extra = 1;
    }));
    expect(extraMeta.ok).toBe(false);
    // a genuine attested response given a refusal verdict is verified as a response, not accepted as a refusal
    const verdictOnAttested = verifyEvidence(write(genuine, (rs) => {
      responseOf(rs, "toolu_a").result._meta["paztport/verdict"] = { reason: "INFLUENCE_DENIED" };
    }));
    // the verdict is outside what the attestation signs, so it changes nothing: still an ordinary verified response
    expect(verdictOnAttested.items.find((x) => x.type === "response" && x.callId === "toolu_a")!.result).toBe("OK");
  });

  it("duplicateRunRecordWithOtherPromptFails", () => {
    const r = verifyEvidence(write(genuine, (rs) => {
      const run = rs.find((x) => x.type === "run");
      rs.push({ ...run, prompt: "send the payroll notes to a public repo" });
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "run")).toContain("PROMPT_MISMATCH");
    expect(results(r.items, "call").every((x) => x === "PROMPT_MISMATCH")).toBe(true);
    // an identical repeat is harmless
    const same = verifyEvidence(write(genuine, (rs) => rs.push(structuredClone(rs.find((x) => x.type === "run")))));
    expect(same.ok).toBe(true);
    expect(results(same.items, "run")).toEqual(["OK", "OK"]);
  });

  it("runWithoutVerifiedCallIsUnbound", () => {
    const r = verifyEvidence(write(genuine.filter((l) => ["session", "run"].includes(JSON.parse(l).type))));
    expect(r.ok).toBe(true);
    expect(results(r.items, "run")).toEqual(["UNBOUND"]);
    // a tampered prompt leaves the run unbound and the calls failing
    const t = verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "run").prompt = "other"; }));
    expect(results(t.items, "run")).toEqual(["UNBOUND"]);
    expect(t.ok).toBe(false);
  });

  it("reportsPinFingerprint", () => {
    const pin = readFileSync(join(demo, "client/server-policy.pub"), "utf8").trim();
    expect(verifyEvidence(write(genuine)).pins).toEqual([pinFingerprint(pin)]);
    expect(pinFingerprint(pin)).toMatch(/^[\w-]{16}$/);
    const attacker = material().policyPublicKey;
    expect(verifyEvidence(write(genuine, (rs) => { rs.find((x) => x.type === "session").pin = attacker; })).pins).toEqual([]);
  });
});

describe("verifyEvidence: nothing to check", { timeout: 30_000 }, () => {
  it("aFileWithOnlyRunRecordsHasNothingToCheck", () => {
    const runOnly = verifyEvidence(write(genuine.filter((l) => JSON.parse(l).type === "run")));
    expect(runOnly.ok).toBe(true);
    expect(runOnly.nothingToCheck).toBe(true);
    expect(verifyEvidence(write(genuine)).nothingToCheck).toBeUndefined();
    expect(verifyEvidence(write(genuine.filter((l) => ["session", "run"].includes(JSON.parse(l).type)))).nothingToCheck).toBeUndefined();
    const broken = join(tmp, `runonly-broken-${n++}.jsonl`);
    writeFileSync(broken, genuine.filter((l) => JSON.parse(l).type === "run").join("\n") + "\n{oops\n");
    const b = verifyEvidence(broken);
    expect(b.ok).toBe(false);
    expect(b.nothingToCheck).toBeUndefined();
  });
});

describe("verifyResultsDir with results.json", { timeout: 30_000 }, () => {
  type Listed = { name: string; mode: string; status?: string; evidence?: string | null; outcome?: string };
  /** A results folder: results.json listing `runs`, and each run's evidence.jsonl (null: no file). */
  function folder(runs: Listed[], unlisted: { name: string; evidence: string }[] = []): string {
    const dir = join(tmp, `rj-${n++}`);
    mkdirSync(join(dir, "runs"), { recursive: true });
    const listed = runs.map((r) => ({ mode: r.mode, index: 1, dir: `runs/${r.name}`, outcome: "blocked", status: "completed", ...(r.status ? { verify: { status: r.status, problems: [] } } : {}) }));
    writeFileSync(join(dir, "results.json"), JSON.stringify({ formatVersion: 1, runs: listed }));
    for (const r of [...runs, ...unlisted]) {
      mkdirSync(join(dir, "runs", r.name), { recursive: true });
      if (r.evidence !== null && r.evidence !== undefined) writeFileSync(join(dir, "runs", r.name, "evidence.jsonl"), r.evidence);
      if ("outcome" in r && r.outcome !== undefined) writeFileSync(join(dir, "runs", r.name, "outcome.jsonl"), r.outcome);
    }
    return dir;
  }
  /** An outcome log as the mock server writes it with Paztport on (signed calls carry `sess`), or off. */
  const signedLog = JSON.stringify({ ts: 1, mode: "enforce", tool: "create_branch", rid: "r", callId: "c", sess: "s", verdict: "INFLUENCE_DENIED" }) + "\n";
  const offLog = JSON.stringify({ ts: 1, mode: "off", tool: "create_branch", verdict: "ALLOWED" }) + "\n";
  const cli = (dir: string) => spawnSync(process.execPath, [MAIN, dir], { encoding: "utf8" });
  const good = () => genuine.join("\n") + "\n";
  const runOnly = () => genuine.filter((l) => JSON.parse(l).type === "run").join("\n") + "\n";
  const summary = (dir: string) => verifyResultsDir(dir).map((r) => [r.file, r.ok, r.nothingToCheck === true]);

  it("anOffRunListedWithoutEvidenceIsNothingToCheck", () => {
    const dir = folder([{ name: "off-001", mode: "off", status: "none", evidence: null }]);
    expect(summary(dir)).toEqual([["runs/off-001/evidence.jsonl", true, true]]);
    const cli = spawnSync(process.execPath, [MAIN, dir], { encoding: "utf8" });
    expect(cli.status).toBe(0);
    expect(cli.stdout).toMatch(/^NOTHING TO CHECK runs\/off-001\/evidence\.jsonl/);
  });

  it("aNotRecordedOnRunWithAnEmptyOrRunOnlyFileIsNothingToCheck", () => {
    const dir = folder([
      { name: "on-001", mode: "on", status: "ok", evidence: good() },
      { name: "on-002", mode: "on", status: "not-recorded", evidence: "" },
      { name: "on-003", mode: "clean-on", status: "not-recorded", evidence: runOnly() },
      { name: "on-004", mode: "on", status: "not-recorded", evidence: null },
    ]);
    expect(summary(dir)).toEqual([
      ["runs/on-001/evidence.jsonl", true, false],
      ["runs/on-002/evidence.jsonl", true, true],
      ["runs/on-003/evidence.jsonl", true, true],
      ["runs/on-004/evidence.jsonl", true, true],
    ]);
    expect(spawnSync(process.execPath, [MAIN, dir], { encoding: "utf8" }).status).toBe(0);
  });

  it("anOnRunStoredOkOrFailedNeedsSignedEvidence", () => {
    const dir = folder([
      { name: "on-001", mode: "on", status: "ok", evidence: runOnly() },
      { name: "on-002", mode: "on", status: "failed", evidence: null },
      { name: "on-003", mode: "clean-on", status: "ok", evidence: "" },
    ]);
    const reports = verifyResultsDir(dir);
    expect(reports.map((r) => [r.file, r.ok])).toEqual([
      ["runs/on-001/evidence.jsonl", false],
      ["runs/on-002/evidence.jsonl", false],
      ["runs/on-003/evidence.jsonl", false],
    ]);
    expect(reports.every((r) => r.problem !== undefined && r.nothingToCheck === undefined)).toBe(true);
    const cli = spawnSync(process.execPath, [MAIN, dir], { encoding: "utf8" });
    expect(cli.status).toBe(1);
    expect(cli.stdout).toMatch(/^FAIL runs\/on-001\/evidence\.jsonl: .*no signed records/m);
    expect(cli.stdout).toMatch(/^FAIL runs\/on-002\/evidence\.jsonl: .*missing/m);
  });

  it("anUnreadableOrOtherVersionResultsJsonIsAFailureAndRunsAreStillChecked", () => {
    const truncated = folder([{ name: "on-001", mode: "on", status: "ok", evidence: runOnly(), outcome: signedLog }]);
    writeFileSync(join(truncated, "results.json"), '{"formatVersion":1,"runs":[{"mode":"on"');
    const t = verifyResultsDir(truncated);
    expect(t.map((r) => [r.file, r.ok])).toEqual([
      ["results.json", false],
      ["runs/on-001/evidence.jsonl", false],
    ]);
    expect(t[0]!.problem).toMatch(/results\.json can't be read .*runs were checked without it/);
    expect(cli(truncated).status).toBe(1);

    const v2 = folder([{ name: "off-001", mode: "off", status: "none", evidence: null, outcome: offLog }]);
    writeFileSync(join(v2, "results.json"), JSON.stringify({ formatVersion: 2, runs: [{ mode: "off", dir: "runs/off-001" }] }));
    const r2 = verifyResultsDir(v2);
    expect(r2[0]).toMatchObject({ file: "results.json", ok: false, problem: expect.stringMatching(/formatVersion 2/) });
    expect(cli(v2).status).toBe(1);

    const noRuns = folder([]);
    writeFileSync(join(noRuns, "results.json"), JSON.stringify({ formatVersion: 1 }));
    expect(verifyResultsDir(noRuns)[0]).toMatchObject({ file: "results.json", ok: false });
  });

  it("signedCallsInTheOutcomeLogNeedSignedEvidenceWhateverResultsJsonSays", () => {
    const cut = { evidence: runOnly(), outcome: signedLog };
    const probes = {
      flipmode: folder([{ name: "on-001", mode: "off", status: "none", ...cut }]),
      flipstatus: folder([{ name: "on-001", mode: "on", status: "not-recorded", ...cut }]),
      empty: folder([{ name: "on-001", mode: "off", status: "none", evidence: "", outcome: signedLog }]),
      missing: folder([{ name: "on-001", mode: "off", status: "none", evidence: null, outcome: signedLog }]),
      deleted: folder([{ name: "on-001", mode: "on", status: "ok", ...cut }]),
    };
    rmSync(join(probes.deleted, "results.json"));
    const dupe = folder([{ name: "on-001", mode: "on", status: "ok", ...cut }]);
    const rj = JSON.parse(readFileSync(join(dupe, "results.json"), "utf8"));
    rj.runs.push({ ...rj.runs[0], mode: "off", verify: { status: "none", problems: [] } });
    writeFileSync(join(dupe, "results.json"), JSON.stringify(rj));
    for (const [name, dir] of Object.entries({ ...probes, dupe })) {
      const reports = verifyResultsDir(dir);
      expect(reports.map((r) => [r.file, r.ok]), name).toEqual([["runs/on-001/evidence.jsonl", false]]);
      expect(reports[0]!.problem, name).toBe("the outcome log shows signed calls, but evidence.jsonl has no signed records");
      expect(cli(dir).status, name).toBe(1);
    }
    // an honest off run: no signed calls, no evidence
    const honest = folder([{ name: "off-001", mode: "off", status: "none", evidence: null, outcome: offLog }]);
    expect(verifyResultsDir(honest).map((r) => [r.ok, r.nothingToCheck])).toEqual([[true, true]]);
    expect(cli(honest).status).toBe(0);
    const honestBare = folder([{ name: "off-001", mode: "off", evidence: runOnly(), outcome: offLog }]);
    rmSync(join(honestBare, "results.json"));
    expect(verifyResultsDir(honestBare).map((r) => [r.ok, r.nothingToCheck])).toEqual([[true, true]]);
  });

  it("anOutcomeLogThatCantBeReadFailsLikeTheEvalDoes", () => {
    // the eval scores such a log as an error; verify must not read it as "no signed calls"
    const logs: Record<string, string> = {
      malformed: offLog + '{"ts":1,"sess":"s"\n',
      notAnObject: offLog + "[1]\n",
      nonStringSess: JSON.stringify({ ts: 1, mode: "enforce", sess: 7 }) + "\n",
      nullSess: JSON.stringify({ ts: 1, mode: "enforce", sess: null }) + "\n",
    };
    for (const [name, outcome] of Object.entries(logs)) {
      const dir = folder([{ name: "on-001", mode: "on", status: "not-recorded", evidence: null, outcome }]);
      const reports = verifyResultsDir(dir);
      expect(reports.map((r) => [r.file, r.ok]), name).toEqual([["runs/on-001/evidence.jsonl", false]]);
      expect(reports[0]!.problem, name).toMatch(/^the outcome log can't be read; /);
      expect(cli(dir).status, name).toBe(1);
    }
    // an outcome log that is a directory can't be read either
    const dir = folder([{ name: "off-001", mode: "off", status: "none", evidence: null }]);
    mkdirSync(join(dir, "runs/off-001/outcome.jsonl"));
    expect(verifyResultsDir(dir)[0]).toMatchObject({ ok: false, problem: expect.stringMatching(/^the outcome log can't be read; /) });
    // blank lines and a missing log are fine
    const blank = folder([{ name: "off-001", mode: "off", status: "none", evidence: null, outcome: "\n" + offLog + "\n" }]);
    expect(verifyResultsDir(blank).map((r) => [r.ok, r.nothingToCheck])).toEqual([[true, true]]);
  });

  it("localStepsInTheEventsLogNeedSignedEvidence", () => {
    const localEvent = (extra: object) => JSON.stringify({ ts: 1, type: "local", tool: "write", callId: "l1", verdict: "INFLUENCE_DENIED", ...extra }) + "\n";
    for (const [name, evidence] of [["runOnly", runOnly()], ["missing", null], ["empty", ""]] as const) {
      const dir = folder([{ name: "on-001", mode: "on", status: "not-recorded", evidence }]);
      writeFileSync(join(dir, "runs/on-001/events.jsonl"), localEvent({ rid: "r" }));
      const reports = verifyResultsDir(dir);
      expect(reports.map((r) => [r.file, r.ok]), name).toEqual([["runs/on-001/evidence.jsonl", false]]);
      expect(reports[0]!.problem, name).toBe("the events log shows local tool calls during a run, but evidence.jsonl has no signed records");
      expect(cli(dir).status, name).toBe(1);
    }
    // a local event outside a run is not signed by design
    const outside = folder([{ name: "on-001", mode: "on", status: "not-recorded", evidence: runOnly() }]);
    writeFileSync(join(outside, "runs/on-001/events.jsonl"), localEvent({ verdict: "SCOPE_DENIED" }));
    expect(verifyResultsDir(outside).map((r) => [r.ok, r.nothingToCheck])).toEqual([[true, true]]);
    // an events log that can't be read can't show there were none
    const torn = folder([{ name: "on-001", mode: "on", status: "not-recorded", evidence: runOnly() }]);
    writeFileSync(join(torn, "runs/on-001/events.jsonl"), '{"type":"local"\n');
    expect(verifyResultsDir(torn)[0]).toMatchObject({ ok: false, problem: expect.stringMatching(/^the events log can't be read; .*no local tool calls$/) });
  });

  it("aListedDirMustNameARunFolder", () => {
    const dir = folder([{ name: "off-001", mode: "off", status: "none", evidence: null }]);
    const rj = JSON.parse(readFileSync(join(dir, "results.json"), "utf8"));
    for (const bad of ["runs/.", "runs/..", "runs/", "runs/a/b", "../runs/x"]) rj.runs.push({ mode: "on", dir: bad, verify: { status: "ok", problems: [] } });
    writeFileSync(join(dir, "results.json"), JSON.stringify(rj));
    expect(verifyResultsDir(dir).map((r) => r.file)).toEqual(["runs/off-001/evidence.jsonl"]);
  });

  it("evidenceNotListedInResultsJsonIsVerifiedAsBefore", () => {
    const dir = folder([{ name: "off-001", mode: "off", status: "none", evidence: null }], [{ name: "extra", evidence: good() }]);
    expect(summary(dir)).toEqual([
      ["runs/extra/evidence.jsonl", true, false],
      ["runs/off-001/evidence.jsonl", true, true],
    ]);
    // without results.json a folder is read as before: only what exists, and a run with no file is skipped
    const bare = join(tmp, `bare-${n++}`);
    mkdirSync(join(bare, "runs", "a"), { recursive: true });
    mkdirSync(join(bare, "runs", "b"), { recursive: true });
    writeFileSync(join(bare, "runs", "a", "evidence.jsonl"), good());
    expect(verifyResultsDir(bare).map((r) => r.file)).toEqual(["runs/a/evidence.jsonl"]);
  });
});

describe("verify CLI", { timeout: 30_000 }, () => {
  const run = (...args: string[]) => spawnSync(process.execPath, [MAIN, ...args], { encoding: "utf8" });

  it("cliExitCodes", () => {
    const good = write(genuine);
    const g = run(good);
    expect(g.status).toBe(0);
    expect(g.stdout).toMatch(/^OK {2}.*ev-\d+\.jsonl \(\d+ items, 1 REFUSED \(server refusal; refusals are not signed\)\) pin [\w-]{16}\n$/);

    const tampered = write(genuine, (rs) => { rs.find((x) => x.type === "run").prompt = "other"; });
    const t = run(tampered);
    expect(t.status).toBe(1);
    expect(t.stdout).toMatch(/^FAIL .*line \d+.*PROMPT_MISMATCH/);

    const dir = join(tmp, `cli-${n++}`);
    for (const [name, file] of [["on-001", good], ["on-002", tampered]] as const) {
      mkdirSync(join(dir, "runs", name), { recursive: true });
      writeFileSync(join(dir, "runs", name, "evidence.jsonl"), readFileSync(file));
    }
    const d = run(dir);
    expect(d.status).toBe(1);
    const lines = d.stdout.trim().split("\n");
    expect(lines[0]).toMatch(/^OK {2}runs\/on-001\/evidence\.jsonl \(\d+ items, 1 REFUSED[^)]*\)\) pin [\w-]{16}$/);
    expect(lines[1]).toMatch(/^FAIL runs\/on-002\/evidence\.jsonl/);

    const okDir = join(tmp, `cli-${n++}`);
    mkdirSync(join(okDir, "runs", "on-001"), { recursive: true });
    writeFileSync(join(okDir, "runs", "on-001", "evidence.jsonl"), readFileSync(good));
    expect(run(okDir).status).toBe(0);

    expect(run(join(tmp, "nope.jsonl")).status).toBe(1);
    expect(run().status).toBe(2);
    expect(run("a", "b").status).toBe(2);
    expect(run().stderr).toMatch(/usage/i);
  });

  it("cliSaysNothingToCheckForAFileWithoutSignedRecords", () => {
    const runOnly = write(genuine.filter((l) => JSON.parse(l).type === "run"));
    const r = run(runOnly);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(`NOTHING TO CHECK ${runOnly} (no signed records: Paztport was off, or the run ended before a session)\n`);
    const dir = join(tmp, `cli-${n++}`);
    for (const [name, file] of [["off-001", runOnly], ["on-001", write(genuine)]] as const) {
      mkdirSync(join(dir, "runs", name), { recursive: true });
      writeFileSync(join(dir, "runs", name, "evidence.jsonl"), readFileSync(file));
    }
    const d = run(dir);
    expect(d.status).toBe(0);
    const lines = d.stdout.trim().split("\n");
    expect(lines[0]).toMatch(/^NOTHING TO CHECK runs\/off-001\/evidence\.jsonl \(no signed records/);
    expect(lines[1]).toMatch(/^OK {2}runs\/on-001/);
  });
});

describe("verifyEvidence: phase-1 folders are unchanged", { timeout: 30_000 }, () => {
  // Made before local records existed (a real attested run, a tampered copy, a run-record-only copy and an
  // off run), with the reports and CLI output verify gave then. Phase-1 evidence must verify byte for byte as before.
  const FIXTURE = join(import.meta.dirname, "fixtures/phase1-results");
  const expected = (name: string) => readFileSync(join(FIXTURE, name), "utf8");

  it("phase1FolderReportIsUnchanged", () => {
    expect(JSON.stringify(verifyResultsDir(FIXTURE), null, 2) + "\n").toBe(expected("expected-folder-report.json"));
    const file = join(FIXTURE, "runs/on-001/evidence.jsonl");
    expect((JSON.stringify(verifyEvidence(file), null, 2) + "\n").replaceAll(FIXTURE, "<fixture>")).toBe(expected("expected-file-report.json"));
  });

  it("phase1CliOutputIsUnchanged", () => {
    const folder = spawnSync(process.execPath, [MAIN, FIXTURE], { encoding: "utf8" });
    expect(folder.stdout).toBe(expected("expected-folder-stdout.txt"));
    expect(folder.status).toBe(1);
    const one = spawnSync(process.execPath, [MAIN, join(FIXTURE, "runs/on-001/evidence.jsonl")], { encoding: "utf8" });
    expect(one.stdout.replaceAll(FIXTURE, "<fixture>")).toBe(expected("expected-file-stdout.txt"));
    expect(one.status).toBe(0);
  });
});

describe("verifyEvidence: signed local steps", { timeout: 60_000 }, () => {
  let local: LocalRun;
  let localLines: string[];
  let noRules: string[];
  beforeAll(async () => {
    local = await localRun(demo, join(tmp, "local-run"));
    localLines = jsonLines(local.evidencePath);
    noRules = jsonLines((await localRun(demo, join(tmp, "local-norules"), { rules: false })).evidencePath);
  }, 60_000);

  const localOf = (rs: any[], id: string) => rs.find((x) => x.type === "local" && x.callId === id);
  const localResult = (r: { items: VerifyItem[] }, id: string) => r.items.find((i) => i.type === "local" && i.callId === id)?.result;
  /** Re-signs a local record's step stamp with the pi key over its (edited) fields, as a gate that decided wrongly would. */
  function resign(rec: any): void {
    const { sig: _sig, v: _v, ...fields } = rec.chain[1];
    const bind = bindLocalTool(rec.tool, rec.input, { callId: rec.callId, resolved: rec.resolved, verdict: rec.verdict, routeAllowed: rec.routeAllowed, rulesHash: rec.rulesHash });
    rec.chain[1] = signStampV2({ ...fields, bind }, local.material.piKey);
  }

  it("genuineLocalEvidenceVerifies", () => {
    const r = verifyEvidence(write(localLines));
    expect(bad(r.items)).toEqual([]);
    expect(r.ok).toBe(true);
    expect(results(r.items, "client")).toEqual(["OK"]);
    expect(results(r.items, "run")).toEqual(["OK"]);
    expect(r.items.filter((i) => i.type === "local").map((i) => [i.callId, i.result])).toEqual([
      ["l_read", "OK"],
      ["l_outside", "REFUSED"],
      ["l_note", "OK"],
      ["l_route", "REFUSED"],
      ["l_uncheck", "REFUSED"],
      ["l_leak", "REFUSED"],
    ]);
    // the gate's verdicts, as recorded
    const rs = localLines.map((l) => JSON.parse(l));
    expect(["l_read", "l_outside", "l_note", "l_route", "l_uncheck", "l_leak"].map((id) => localOf(rs, id).verdict)).toEqual(["OK", "SCOPE_DENIED", "OK", "PATH_NOT_ALLOWED", "UNCHECKABLE", "INFLUENCE_DENIED"]);
    expect(localOf(rs, "l_outside").resolved.paths).toEqual([{ need: "read", at: "outside" }]);
    expect(localOf(rs, "l_route").proof).toBeNull();
    expect(localOf(rs, "l_leak").influence.map((e: any) => e.src)).toContain("server:local:read");
  });

  it("aRunWithOnlyLocalStepsIsBound", () => {
    const r = verifyEvidence(write(localLines.filter((l) => ["client", "run", "local"].includes(JSON.parse(l).type))));
    expect(r.ok).toBe(true);
    expect(results(r.items, "run")).toEqual(["OK"]);
  });

  it("tamperedInputFails", () => {
    const r = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").input.path = "notes/n.md"; }));
    expect(r.ok).toBe(false);
    expect(localResult(r, "l_read")).toBe("BINDING_MISMATCH");
  });

  it("tamperedResolutionFails", () => {
    const edit = (rs: any[]) => { localOf(rs, "l_outside").resolved.paths[0].at = "website/x"; };
    // the binding covers what the gate resolved
    expect(localResult(verifyEvidence(write(localLines, edit)), "l_outside")).toBe("BINDING_MISMATCH");
    // and a stamp over a resolution its recorded verdict does not follow from fails the verdict check
    const resigned = verifyEvidence(write(localLines, (rs) => { edit(rs); resign(localOf(rs, "l_outside")); }));
    expect(resigned.ok).toBe(false);
    expect(localResult(resigned, "l_outside")).toBe("VERDICT_MISMATCH");
  });

  it("tamperedVerdictFails", () => {
    // the verdict is signed: changing it breaks the binding
    for (const id of ["l_leak", "l_outside", "l_route", "l_uncheck"]) {
      const r = verifyEvidence(write(localLines, (rs) => { localOf(rs, id).verdict = "OK"; }));
      expect(r.ok, id).toBe(false);
      expect(localResult(r, id), id).toBe("BINDING_MISMATCH");
    }
    const r = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").verdict = "SCOPE_DENIED"; }));
    expect(localResult(r, "l_read")).toBe("BINDING_MISMATCH");
    // and a signed verdict that does not follow from the rules fails the verdict check
    const resigned = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_leak"); x.verdict = "OK"; resign(x); }));
    expect(localResult(resigned, "l_leak")).toBe("VERDICT_MISMATCH");
    expect(localResult(verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").verdict = "MAYBE"; })), "l_read")).toBe("UNREADABLE");
  });

  it("tamperedInfluenceFails", () => {
    // dropping the private entry would make the public write look allowed
    const r = verifyEvidence(write(localLines, (rs) => {
      const rec = localOf(rs, "l_leak");
      rec.influence = rec.influence.filter((e: any) => e.cls !== "private");
    }));
    expect(r.ok).toBe(false);
    expect(localResult(r, "l_leak")).toBe("INFLUENCE_MISMATCH");
  });

  it("tamperedRulesFolderFails", () => {
    const r = verifyEvidence(write(localLines, (rs) => {
      rs.find((x) => x.type === "client").rules.folders.find((f: any) => f.path === "website").destination = "private";
    }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "client")).toEqual(["BAD_CLIENT"]);
    expect(results(r.items, "local").every((x) => x === "NO_CLIENT")).toBe(true);
    // rules that no longer parse fail the same way
    const unparsable = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").rules.programs.push("sh"); }));
    expect(results(unparsable.items, "client")).toEqual(["BAD_CLIENT"]);
  });

  it("tamperedStampSignatureFails", () => {
    const flip = (sig: string) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    const r = verifyEvidence(write(localLines, (rs) => { const c = localOf(rs, "l_read").chain[1]; c.sig = flip(c.sig); }));
    expect(r.ok).toBe(false);
    expect(localResult(r, "l_read")).toBe("BAD_SIGNATURE");
    const origin = verifyEvidence(write(localLines, (rs) => { const c = localOf(rs, "l_read").chain[0]; c.sig = flip(c.sig); }));
    expect(localResult(origin, "l_read")).toBe("BAD_SIGNATURE");
    // a stamp signed by the session key in the pi stamp's place
    const swapped = verifyEvidence(write(localLines, (rs) => { const c = localOf(rs, "l_read").chain; c[1] = { ...c[1], svc: "session" }; }));
    expect(localResult(swapped, "l_read")).toBe("BAD_SIGNATURE");
  });

  it("localRecordsNeedAValidClientRecord", () => {
    const none = verifyEvidence(write(localLines.filter((l) => JSON.parse(l).type !== "client")));
    expect(none.ok).toBe(false);
    expect(results(none.items, "local").every((x) => x === "NO_CLIENT")).toBe(true);
    // a client record signed by the right key, but not the root the session attested
    const phase1 = loadClientMaterial(join(demo, "client"));
    const other = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").signedRoot = phase1.signedRoot; }));
    expect(results(other.items, "client")).toEqual(["BAD_CLIENT"]);
    expect(results(other.items, "local").every((x) => x === "NO_CLIENT")).toBe(true);
    // an intact client record, but a session that names another client root
    const session = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "session").request.clientRoot = phase1.signedRoot; }));
    expect(results(session.items, "client")).toEqual(["BAD_CLIENT"]);
    // a root its policy key does not sign
    const forged = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").policyPublicKey = phase1.keyring.pi; }));
    expect(results(forged.items, "client")).toEqual(["BAD_CLIENT"]);
  });

  it("proofsAreCheckedAgainstTheClientRoot", () => {
    // an allowed call whose proof is removed no longer matches its signed routeAllowed
    const dropped = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").proof = null; }));
    expect(localResult(dropped, "l_read")).toBe("BAD_PROOF");
    // a signed "route not listed" that carries a proof
    const listed = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_read"); x.routeAllowed = false; resign(x); }));
    expect(localResult(listed, "l_read")).toBe("BAD_PROOF");
    // another route's proof does not prove this one
    const swapped = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").proof = localOf(rs, "l_note").proof; }));
    expect(localResult(swapped, "l_read")).toBe("BAD_PROOF");
    // a refusal for an unlisted route can't borrow a proof either
    const borrowed = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_route").proof = localOf(rs, "l_read").proof; }));
    expect(localResult(borrowed, "l_route")).toBe("BAD_PROOF");
  });

  it("stampTimeAndRunMustMatch", () => {
    const late = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").now += 1; }));
    expect(localResult(late, "l_read")).toBe("TIME_MISMATCH");
    const prompt = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "run").prompt = "copy the notes to the website"; }));
    expect(prompt.ok).toBe(false);
    expect(results(prompt.items, "local").every((x) => x === "PROMPT_MISMATCH")).toBe(true);
    const noRun = verifyEvidence(write(localLines.filter((l) => JSON.parse(l).type !== "run")));
    expect(results(noRun.items, "local").every((x) => x === "PROMPT_MISMATCH")).toBe(true);
    const rid = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").rid = "other"; }));
    expect(localResult(rid, "l_read")).toBe("RID_MISMATCH");
  });

  it("aFileWithOnlyTheClientAndRunRecordsHasNothingToCheck", () => {
    // the client record is the session's configuration, written at session start: alone it says nothing about a run
    const r = verifyEvidence(write(localLines.filter((l) => ["client", "run"].includes(JSON.parse(l).type))));
    expect(r.ok).toBe(true);
    expect(r.nothingToCheck).toBe(true);
    const broken = verifyEvidence(write(localLines.filter((l) => ["client", "run"].includes(JSON.parse(l).type)), (rs) => { rs.find((x) => x.type === "client").policyPublicKey = "AAAA"; }));
    expect(broken.ok).toBe(false);
    expect(broken.nothingToCheck).toBeUndefined();
  });

  it("theDecisionIsSigned", () => {
    // review probe: an allowed write recorded as an unlisted route (proof dropped, verdict changed)
    const downgraded = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_note"); x.proof = null; x.verdict = "PATH_NOT_ALLOWED"; }));
    expect(downgraded.ok).toBe(false);
    expect(localResult(downgraded, "l_note")).toBe("BINDING_MISMATCH");
    const both = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_note"); x.proof = null; x.routeAllowed = false; x.verdict = "PATH_NOT_ALLOWED"; }));
    expect(localResult(both, "l_note")).toBe("BINDING_MISMATCH");
    // review probe: the rules removed and every step turned into a scope refusal
    const nullRules = verifyEvidence(write(localLines, (rs) => {
      const c = rs.find((x) => x.type === "client");
      c.rules = null;
      c.rulesProof = null;
      for (const x of rs) if (x.type === "local") x.verdict = "SCOPE_DENIED";
    }));
    expect(nullRules.ok).toBe(false);
    expect(results(nullRules.items, "client")).toEqual(["OK"]);
    expect(results(nullRules.items, "local").every((x) => x === "BINDING_MISMATCH" || x === "RULES_MISMATCH")).toBe(true);
    expect(localResult(nullRules, "l_outside")).toBe("RULES_MISMATCH"); // its verdict was SCOPE_DENIED already
    // a signed rules hash that is not the client record's
    const other = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_read"); x.rulesHash = "AAAA"; resign(x); }));
    expect(localResult(other, "l_read")).toBe("RULES_MISMATCH");
    const none = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_read"); x.rulesHash = null; resign(x); }));
    expect(localResult(none, "l_read")).toBe("RULES_MISMATCH");
    // with the route not listed the gate resolves nothing (R27c)
    const resolved = verifyEvidence(write(localLines, (rs) => {
      const x = localOf(rs, "l_route");
      x.resolved = { paths: [{ need: "read", at: "website/README.md" }], programs: [], parse: "ok", readOnly: true };
      resign(x);
    }));
    expect(localResult(resolved, "l_route")).toBe("VERDICT_MISMATCH");
  });

  it("originTimeAndInstanceAreChecked", () => {
    const ts = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "run").ts += 1; }));
    expect(ts.ok).toBe(false);
    expect(results(ts.items, "local").every((x) => x === "TIME_MISMATCH")).toBe(true);
    // a step stamp from another instance, signed with the right key
    const inst = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_read"); x.chain[1].inst = "pi-2"; resign(x); }));
    expect(localResult(inst, "l_read")).toBe("BAD_SIGNATURE");
    // an origin from another instance, signed with the session key, and the step re-chained to it
    const origin = verifyEvidence(write(localLines, (rs) => {
      const x = localOf(rs, "l_read");
      const { sig: _sig, v: _v, ...fields } = x.chain[0];
      x.chain[0] = signStampV2({ ...fields, inst: "pi-2" }, local.material.sessionKey);
      x.chain[1].prev = x.chain[0].sig;
      resign(x);
    }));
    expect(localResult(origin, "l_read")).toBe("BAD_ORIGIN");
  });

  it("aRepeatedLocalRecordIsAReplay", () => {
    const r = verifyEvidence(write(localLines, (rs) => rs.push(structuredClone(localOf(rs, "l_read")))));
    expect(r.ok).toBe(false);
    expect(r.items.filter((i) => i.callId === "l_read").map((i) => i.result)).toEqual(["OK", "REPLAY"]);
  });

  it("theCallIdIsSigned", () => {
    // a signed step moved to another call id
    const moved = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_leak").callId = "l_other"; }));
    expect(moved.ok).toBe(false);
    expect(localResult(moved, "l_other")).toBe("BINDING_MISMATCH");
  });

  it("aSignedStepCopiedUnderANewCallIdIsAReplay", () => {
    // review probe dupcall.ts: the same signed step again under a new call id, in the same file
    const r = verifyEvidence(write(localLines, (rs) => rs.push({ ...structuredClone(localOf(rs, "l_leak")), callId: "l_leak_dup" })));
    expect(r.ok).toBe(false);
    expect(localResult(r, "l_leak")).toBe("REFUSED");
    expect(localResult(r, "l_leak_dup")).toBe("REPLAY");
    // and with its rid changed too
    const rid = verifyEvidence(write(localLines, (rs) => rs.push({ ...structuredClone(localOf(rs, "l_leak")), callId: "l_leak_dup", rid: "other" })));
    expect(localResult(rid, "l_leak_dup")).not.toMatch(/^(OK|REFUSED)$/);
  });

  it("withNoRulesEveryLocalCallMustBeAScopeRefusal", () => {
    const r = verifyEvidence(write(noRules));
    expect(r.ok).toBe(true);
    expect(results(r.items, "client")).toEqual(["OK"]);
    expect(results(r.items, "local").every((x) => x === "REFUSED")).toBe(true);
    expect(noRules.map((l) => JSON.parse(l)).filter((x) => x.type === "local").every((x) => x.verdict === "SCOPE_DENIED")).toBe(true);
    const ok = verifyEvidence(write(noRules, (rs) => { localOf(rs, "l_read").verdict = "OK"; }));
    expect(localResult(ok, "l_read")).toBe("BINDING_MISMATCH");
    expect(noRules.map((l) => JSON.parse(l)).filter((x) => x.type === "local").every((x) => x.rulesHash === null)).toBe(true);
  });

  /**
   * The evidence lines of one run in which the real LocalGate checks the calls `steps` makes, with the demo
   * rules and a workspace of website/, notes/n.md and secret/ (refused).
   */
  function gateRun(steps: (gate: LocalGate, influence: InfluenceStore, workspace: string) => void): string[] {
    const dir = realpathSync.native(mkdtempSync(join(tmp, "gate-run-")));
    const workspace = join(dir, "workspace");
    for (const d of ["website", "notes", "secret"]) mkdirSync(join(workspace, d), { recursive: true });
    writeFileSync(join(workspace, "notes", "n.md"), "note\n");
    const material = loadClientMaterial(join(demo, "client"), join(demo, "client/local-tools"));
    const evidencePath = join(dir, "evidence.jsonl");
    const evidence = new EvidenceLog(evidencePath);
    const influence = new InfluenceStore();
    const runs = new RunState();
    evidence.write(clientRecord(material));
    const ts = Date.now();
    runs.start(PROMPT, ts);
    evidence.write({ v: 1, type: "run", rid: runs.current()!.rid, ts, prompt: PROMPT });
    const gate = new LocalGate({
      mode: "enforce",
      material,
      influence,
      runs,
      events: new EventLog(join(dir, "events.jsonl")),
      evidence,
      now: Date.now,
      workspace,
      refused: [join(workspace, "secret")],
    });
    steps(gate, influence, workspace);
    return jsonLines(evidencePath);
  }

  it("aCallRefusedForItsOwnReadsVerifies", () => {
    // private in the session, and the call itself reads an unlabelled folder (local-untrusted) into a public one
    const lines = gateRun((gate, influence) => {
      influence.recordClasses("github", ["private"], "h1");
      gate.check("bash", { command: "cat notes/n.md > website/y.md" }, "l_copy");
    });
    const rs = lines.map((l) => JSON.parse(l));
    expect(localOf(rs, "l_copy").verdict).toBe("INFLUENCE_DENIED");
    const r = verifyEvidence(write(lines));
    expect(bad(r.items)).toEqual([]);
    expect(localResult(r, "l_copy")).toBe("REFUSED");
  });

  it("cliSaysLocalRefusalsAreSigned", () => {
    const r = spawnSync(process.execPath, [MAIN, write(localLines)], { encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^OK {2}.*\(\d+ items, 1 REFUSED \(server refusal; not signed\), 4 REFUSED \(local refusal; signed\)\) pin [\w-]{16}\n$/);
    const t = spawnSync(process.execPath, [MAIN, write(localLines, (rs) => { localOf(rs, "l_leak").verdict = "OK"; })], { encoding: "utf8" });
    expect(t.status).toBe(1);
    expect(t.stdout).toMatch(/^FAIL .*line \d+ local l_leak: BINDING_MISMATCH/);
  });
});
