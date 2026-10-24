// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindMcpCall, buildTree, commitInfluence, encode, randomBytes, signStampV2 } from "@paztport/path-attest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ServerConnection } from "../../pi-extension/src/connection.ts";
import { EventLog } from "../../pi-extension/src/events.ts";
import { EvidenceLog } from "../../pi-extension/src/evidence.ts";
import { InfluenceStore } from "../../pi-extension/src/influence.ts";
import { loadClientMaterial } from "../../pi-extension/src/keys.ts";
import { RunState } from "../../pi-extension/src/runs.ts";
import { githubArgs, setupDemo } from "../../pi-extension/test/helpers/demo.ts";
import { pinFingerprint, verifyEvidence, verifyResultsDir, type VerifyItem } from "../src/verify.ts";

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
});
