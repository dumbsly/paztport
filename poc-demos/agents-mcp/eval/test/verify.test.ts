// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindLocalTool, buildTree, commitInfluence, encode, randomBytes, signSessionReply, signStampV2, signStampV3 } from "@paztport/core";
import { bindMcpCall } from "@paztport/mcp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ServerConnection } from "../../pi-extension/src/connection.ts";
import { EventLog } from "../../pi-extension/src/events.ts";
import { clientRecord, EvidenceLog } from "../../pi-extension/src/evidence.ts";
import { InfluenceStore } from "../../pi-extension/src/influence.ts";
import { loadClientMaterial, type ClientMaterial } from "../../pi-extension/src/keys.ts";
import { LocalGate } from "../../pi-extension/src/local/gate.ts";
import { RunState } from "../../pi-extension/src/runs.ts";
import { githubArgs, resignDemo, setupDemo, type DemoWindows } from "../../pi-extension/test/helpers/demo.ts";
import { verifyClient, verifyLocal } from "../src/verify-local.ts";
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

/** A real attested run against the mock server (the demo keys in `dir`): three reads, then a write the server refuses. */
async function produce(pin = join(demo, "client/server-policy.pub"), dir = demo): Promise<string[]> {
  const evidencePath = join(tmp, `gen-${n++}.jsonl`);
  const evidence = new EvidenceLog(evidencePath);
  const runs = new RunState();
  const conn = new ServerConnection(
    { id: "github", command: process.execPath, args: githubArgs(dir, "enforce", join(tmp, `outcome-${n++}.jsonl`)), attested: true, pin },
    "enforce",
    loadClientMaterial(join(dir, "client"), join(dir, "client"), Date.now(), () => {}),
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
  it("freshRunIsNotLegacy", () => {
    const r = verifyEvidence(write(genuine));
    expect(r.ok).toBe(true);
    expect(r.items.filter((i) => i.legacy !== undefined)).toEqual([]);
  });

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

  /** A genuinely signed later call (call id `id`, stamped `gapMs` after toolu_a), as a live clock would give. */
  function lateCall(rs: any[], gapMs: number, id = "toolu_late"): any {
    const a = callOf(rs, "toolu_a");
    const late = structuredClone(a);
    late.callId = id;
    late.now = a.now + gapMs;
    const meta = late.params._meta;
    meta["paztport/callId"] = id;
    const { sig: _sig, v: _v, ...fields } = meta["paztport/chain"][1];
    meta["paztport/chain"][1] = signStampV3(
      { ...fields, ts: late.now, bind: bindMcpCall(late.params.name, id, late.params.arguments), prev: meta["paztport/chain"][0].sig },
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

  it("aNewFormHandshakeVerifies", () => {
    const s = JSON.parse(genuine.find((l) => JSON.parse(l).type === "session")!);
    // the mock server signs its reply with mcp-entry's key, under its keyring's signature and its certificate
    expect(s.reply).toMatchObject({ serverKeyringSig: expect.any(String), serverReplyCert: { svc: "mcp-entry", key: s.reply.serverKeyring["mcp-entry"] } });
    const r = verifyEvidence(write(genuine));
    expect(results(r.items, "session")).toEqual(["OK"]);
    expect(r.items.find((i) => i.type === "session")!.legacy).toBeUndefined();
    // stripped of the certificate, the reply is judged in the policy-key form, which its signature fails
    const stripped = verifyEvidence(write(genuine, (rs) => { delete rs.find((x) => x.type === "session").reply.serverReplyCert; }));
    expect(results(stripped.items, "session")).toEqual(["BAD_SESSION"]);
  });

  it("aFreshSetupsHandshakeIsNewFormOnBothSidesAndVerifies", () => {
    const s = JSON.parse(genuine.find((l) => JSON.parse(l).type === "session")!);
    expect(s.request.clientKeyringNotAfter).toEqual(expect.any(Number));
    expect(s.request.clientRoot.notAfter).toEqual(expect.any(Number));
    expect(s.reply.serverKeyringNotAfter).toEqual(expect.any(Number));
    expect(s.reply.serverRoot.notAfter).toEqual(expect.any(Number));
    const r = verifyEvidence(write(genuine));
    expect(r.ok).toBe(true);
    expect(results(r.items, "session")).toEqual(["OK"]);
    // a window moved in the record fails the keyring or root signature it is covered by. The server's windows are in
    // the reply, which the entry key signs: the reply is signed again over the moved window, as a server holding that
    // key could, so its own signature holds and only the policy key's signature over the window can fail
    const session = (rs: any[]) => rs.find((x) => x.type === "session");
    const entryKey = readFileSync(join(demo, "server/mcp-entry.key"), "utf8").trim();
    const resignReply = (rs: any[]) => {
      const { sig: _sig, ...body } = session(rs).reply;
      session(rs).reply = signSessionReply(body, entryKey);
    };
    expect(results(verifyEvidence(write(genuine, resignReply)).items, "session")).toEqual(["OK"]);
    for (const [what, edit] of [
      ["client keyring", (rs: any[]) => { session(rs).request.clientKeyringNotAfter += 1; }],
      ["client keyring dropped", (rs: any[]) => { delete session(rs).request.clientKeyringNotAfter; }],
      ["client root", (rs: any[]) => { session(rs).request.clientRoot.notAfter += 1; }],
      ["server keyring", (rs: any[]) => { session(rs).reply.serverKeyringNotAfter += 1; resignReply(rs); }],
      ["server root", (rs: any[]) => { session(rs).reply.serverRoot.notAfter += 1; resignReply(rs); }],
      ["malformed client keyring", (rs: any[]) => { session(rs).request.clientKeyringNotAfter = "x"; }],
    ] as [string, (rs: any[]) => void][]) {
      const bad = verifyEvidence(write(genuine, edit));
      expect(results(bad.items, "session"), what).toEqual(["BAD_SESSION"]);
      expect(bad.ok, what).toBe(false);
    }
  });

  it("aCallRecordedAfterTheCertificatesNotAfterIsNotAttested", () => {
    // calls stamped at the certificate's notAfter and 1 ms after it, both signed by the client; each with its own
    // origin at that time, as a run started then would have, so the run's age window is not what refuses them
    const at = (rs: any[], ts: number, id: string) => {
      const c = lateCall(rs, ts - callOf(rs, "toolu_a").now, id);
      const chain = c.params._meta["paztport/chain"];
      const { sig: _o, v: _ov, ...origin } = chain[0];
      chain[0] = signStampV3({ ...origin, ts }, material().sessionKey);
      const { sig: _p, v: _pv, ...hop } = chain[1];
      chain[1] = signStampV3({ ...hop, prev: chain[0].sig }, material().piKey);
      return c;
    };
    const notAfter = (rs: any[]) => rs.find((x) => x.type === "session").reply.serverReplyCert.notAfter as number;
    const r = verifyEvidence(write(genuine, (rs) => {
      const i = rs.indexOf(callOf(rs, "toolu_a"));
      rs.splice(i + 1, 0, at(rs, notAfter(rs), "toolu_on_time"), at(rs, notAfter(rs) + 1, "toolu_late"));
    }));
    expect(r.ok).toBe(false);
    // the session is attested, but only for calls recorded up to its certificate's notAfter
    expect(results(r.items, "session")).toEqual(["OK"]);
    const calls = r.items.filter((x) => x.type === "call").map((x) => [x.callId, x.result]);
    expect(calls).toEqual([
      ["toolu_a", "OK"],
      ["toolu_on_time", "OK"],
      ["toolu_late", "OUTSIDE_SESSION"],
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

describe("verifyEvidence: keyring and root lifetimes", { timeout: 60_000 }, () => {
  // Each record is judged at its own signed time: a call at its last stamp's ts (TIME_MISMATCH ties the record's `now`
  // to it), a local step likewise, a response at the time the client recorded checking it. A window here is ten
  // minutes off and the rest thirty days, so each test isolates one window.
  const callOf = (rs: any[], id: string) => rs.find((x) => x.type === "call" && x.callId === id);
  /** A genuine run against a copy of the demo with `windows` signed in, and that copy's client material. */
  async function runWith(windows: DemoWindows): Promise<{ lines: string[]; material: ClientMaterial; dir: string }> {
    const dir = resignDemo(demo, join(tmp, `resigned-${n++}`), windows);
    const lines = await produce(join(dir, "client/server-policy.pub"), dir);
    return { lines, material: loadClientMaterial(join(dir, "client"), join(dir, "client"), Date.now(), () => {}), dir };
  }
  /** A copy of toolu_a made at `ts`, origin and hop signed by the client then, as a later run's call would be. */
  function callAt(rs: any[], ts: number, id: string, m: ClientMaterial): any {
    const c = structuredClone(callOf(rs, "toolu_a"));
    c.callId = id;
    c.now = ts;
    const meta = c.params._meta;
    meta["paztport/callId"] = id;
    const chain = meta["paztport/chain"];
    const { sig: _o, v: _ov, ...origin } = chain[0];
    chain[0] = signStampV3({ ...origin, ts }, m.sessionKey);
    const { sig: _p, v: _pv, ...hop } = chain[1];
    chain[1] = signStampV3({ ...hop, ts, bind: bindMcpCall(c.params.name, id, c.params.arguments), prev: chain[0].sig }, m.piKey);
    return c;
  }
  /** The calls of `lines` with two copies of toolu_a after it, at `t` and 1 ms after, reported by call id. */
  function callsAround(lines: string[], t: number, m: ClientMaterial): { session: string[]; calls: string[][] } {
    const r = verifyEvidence(write(lines, (rs) => {
      rs.splice(rs.indexOf(callOf(rs, "toolu_a")) + 1, 0, callAt(rs, t, "toolu_on_time", m), callAt(rs, t + 1, "toolu_late", m));
    }));
    return { session: results(r.items, "session"), calls: r.items.filter((x) => x.type === "call").map((x) => [x.callId!, x.result]) };
  }
  const AROUND = [["toolu_a", "OK"], ["toolu_on_time", "OK"], ["toolu_late", "OUTSIDE_SESSION"], ["toolu_b", "OK"], ["toolu_c", "OK"], ["toolu_d", "OK"]];

  it("callAfterClientKeyringNotAfterNotAttested", async () => {
    const t = Date.now() + 600_000;
    const { lines, material } = await runWith({ clientKeyring: t });
    expect(JSON.parse(lines.find((l) => JSON.parse(l).type === "session")!).request.clientKeyringNotAfter).toBe(t);
    // the session is found (it was attested before t), and counts for the calls up to t only
    expect(callsAround(lines, t, material)).toEqual({ session: ["OK"], calls: AROUND });
  });

  it("callAfterServerRootNotAfterNotAttested", async () => {
    const t = Date.now() + 600_000;
    const { lines, material } = await runWith({ serverRoot: t });
    expect(JSON.parse(lines.find((l) => JSON.parse(l).type === "session")!).reply.serverRoot.notAfter).toBe(t);
    expect(callsAround(lines, t, material)).toEqual({ session: ["OK"], calls: AROUND });
  });

  it("callAfterClientRootOrServerKeyringNotAfterNotAttested", async () => {
    for (const w of ["clientRoot", "serverKeyring"] as const) {
      const t = Date.now() + 600_000;
      const { lines, material } = await runWith({ [w]: t });
      expect(callsAround(lines, t, material), w).toEqual({ session: ["OK"], calls: AROUND });
    }
  });

  it("aResponseRecordedAfterTheServersWindowIsPolicyExpired", async () => {
    // the client's live check is limited by the server's root and keyring windows, and so is its recheck: past either the
    // response is POLICY_EXPIRED before any stamp is read; at the window it is judged as usual (EXPIRED: the stamps are
    // ten minutes older than the time recorded). The client's own windows do not limit a response.
    const responseAt = (lines: string[], at: number) =>
      verifyEvidence(write(lines, (rs) => { rs.find((x) => x.type === "response" && x.callId === "toolu_a").now = at; })).items.find((i) => i.type === "response" && i.callId === "toolu_a")!.result;
    for (const [w, past] of [["serverRoot", "POLICY_EXPIRED"], ["serverKeyring", "POLICY_EXPIRED"], ["clientKeyring", "EXPIRED"], ["clientRoot", "EXPIRED"]] as const) {
      const t = Date.now() + 600_000;
      const { lines } = await runWith({ [w]: t });
      expect(responseAt(lines, t), w).toBe("EXPIRED");
      expect(responseAt(lines, t + 1), w).toBe(past);
    }
  });

  it("aWindowEarlierThanTheHandshakeLeavesNoSessionToFind", async () => {
    // a record moved to before its window cannot help: the session is judged at the earliest window, and every signature
    // it rests on is still checked there
    const t = Date.now() + 600_000;
    const { lines } = await runWith({ clientKeyring: t });
    const moved = verifyEvidence(write(lines, (rs) => { rs.find((x) => x.type === "session").request.clientKeyringNotAfter = 0; }));
    expect(results(moved.items, "session")).toEqual(["BAD_SESSION"]);
  });
});

describe("verifyEvidence: the demo page's recorded run is unchanged", () => {
  // A real attested run that the demo page replays: its report, item by item, is the one pinned beside it.
  const FIXTURE = join(import.meta.dirname, "../../demo-ui/test/fixtures/recorded-on-run");

  it("recordedOnRunReportIsUnchanged", () => {
    const report = (JSON.stringify(verifyEvidence(join(FIXTURE, "evidence.jsonl")), null, 2) + "\n").replaceAll(FIXTURE, "<fixture>");
    expect(report).toBe(readFileSync(join(FIXTURE, "expected-verify-report.json"), "utf8"));
  });
});

describe("verifyEvidence: the pinned results folder is unchanged", { timeout: 30_000 }, () => {
  // A real attested run, a copy with one call's repo changed, a copy cut down to its run record and an off run, with the
  // reports and CLI output verify gave for them.
  const FIXTURE = join(import.meta.dirname, "fixtures/eval-results");
  const expected = (name: string) => readFileSync(join(FIXTURE, name), "utf8");

  it("folderReportIsUnchanged", () => {
    expect(JSON.stringify(verifyResultsDir(FIXTURE), null, 2) + "\n").toBe(expected("expected-folder-report.json"));
    const file = join(FIXTURE, "runs/on-001/evidence.jsonl");
    expect((JSON.stringify(verifyEvidence(file), null, 2) + "\n").replaceAll(FIXTURE, "<fixture>")).toBe(expected("expected-file-report.json"));
  });

  it("cliOutputIsUnchanged", () => {
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
    rec.chain[1] = signStampV3({ ...fields, bind }, local.material.piKey);
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
    const noRulesClient = loadClientMaterial(join(demo, "client"));
    const other = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").signedRoot = noRulesClient.signedRoot; }));
    expect(results(other.items, "client")).toEqual(["BAD_CLIENT"]);
    expect(results(other.items, "local").every((x) => x === "NO_CLIENT")).toBe(true);
    // an intact client record, but a session that names another client root
    const session = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "session").request.clientRoot = noRulesClient.signedRoot; }));
    expect(results(session.items, "client")).toEqual(["BAD_CLIENT"]);
    // a root its policy key does not sign
    const forged = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").policyPublicKey = noRulesClient.keyring.pi; }));
    expect(results(forged.items, "client")).toEqual(["BAD_CLIENT"]);
  });

  it("aClientRecordsKeyringSignatureMustVerify", () => {
    const flip = (sig: string) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    expect(typeof localLines.map((l) => JSON.parse(l)).find((x) => x.type === "client").keyringSig).toBe("string");
    const r = verifyEvidence(write(localLines, (rs) => { const c = rs.find((x) => x.type === "client"); c.keyringSig = flip(c.keyringSig); }));
    expect(r.ok).toBe(false);
    expect(results(r.items, "client")).toEqual(["BAD_CLIENT"]);
    expect(results(r.items, "local").every((x) => x === "NO_CLIENT")).toBe(true);
    for (const sig of [null, 1, ""]) {
      const malformed = verifyEvidence(write(localLines, (rs) => { rs.find((x) => x.type === "client").keyringSig = sig; }));
      expect(results(malformed.items, "client"), String(sig)).toEqual(["BAD_CLIENT"]);
    }
    // a client record from before keyrings were signed has no keyringSig (nor a window), and still verifies
    const legacy = verifyEvidence(write(localLines, (rs) => { const c = rs.find((x) => x.type === "client"); delete c.keyringSig; delete c.keyringNotAfter; }));
    expect(results(legacy.items, "client")).toEqual(["OK"]);
    expect(legacy.ok).toBe(true);
    // but a window with no signature to cover it is no record any writer made
    const unsigned = verifyEvidence(write(localLines, (rs) => { delete rs.find((x) => x.type === "client").keyringSig; }));
    expect(results(unsigned.items, "client")).toEqual(["BAD_CLIENT"]);
  });

  it("aNewFormClientRecordVerifiesAndItsWindowsAreSigned", () => {
    const client = (rs: any[]) => rs.find((x) => x.type === "client");
    const rec = client(localLines.map((l) => JSON.parse(l)));
    expect(rec.keyringNotAfter).toEqual(expect.any(Number));
    expect(rec.signedRoot.notAfter).toEqual(expect.any(Number));
    expect(results(verifyEvidence(write(localLines)).items, "client")).toEqual(["OK"]);
    for (const [what, edit] of [
      ["keyring window moved", (rs: any[]) => { client(rs).keyringNotAfter += 1; }],
      ["keyring window dropped", (rs: any[]) => { delete client(rs).keyringNotAfter; }],
      ["keyring window not an integer", (rs: any[]) => { client(rs).keyringNotAfter = 1.5; }],
      ["keyring window null", (rs: any[]) => { client(rs).keyringNotAfter = null; }],
      ["root window moved", (rs: any[]) => { client(rs).signedRoot.notAfter += 1; }],
      ["root window not an integer", (rs: any[]) => { client(rs).signedRoot.notAfter = "x"; }],
      ["a session naming another window", (rs: any[]) => { rs.find((x) => x.type === "session").request.clientKeyringNotAfter += 1; }],
    ] as [string, (rs: any[]) => void][]) {
      const r = verifyEvidence(write(localLines, edit));
      expect(results(r.items, "client"), what).toEqual(["BAD_CLIENT"]);
      expect(results(r.items, "local").every((x) => x === "NO_CLIENT"), what).toBe(true);
    }
  });

  it("proofsAreCheckedAgainstTheClientRoot", () => {
    // an allowed call whose proof is removed no longer matches its signed routeAllowed
    const dropped = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").proof = null; }));
    expect(localResult(dropped, "l_read")).toBe("PROOF_MISMATCH");
    // a signed "route not listed" that carries a proof
    const listed = verifyEvidence(write(localLines, (rs) => { const x = localOf(rs, "l_read"); x.routeAllowed = false; resign(x); }));
    expect(localResult(listed, "l_read")).toBe("PROOF_MISMATCH");
    // another route's proof does not prove this one
    const swapped = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_read").proof = localOf(rs, "l_note").proof; }));
    expect(localResult(swapped, "l_read")).toBe("PROOF_MISMATCH");
    // a refusal for an unlisted route can't borrow a proof either
    const borrowed = verifyEvidence(write(localLines, (rs) => { localOf(rs, "l_route").proof = localOf(rs, "l_read").proof; }));
    expect(localResult(borrowed, "l_route")).toBe("PROOF_MISMATCH");
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
      x.chain[0] = signStampV3({ ...fields, inst: "pi-2" }, local.material.sessionKey);
      x.chain[1].prev = x.chain[0].sig;
      resign(x);
    }));
    expect(localResult(origin, "l_read")).toBe("BAD_ORIGIN");
  });

  it("verifyLocalSaysWhetherAStepIsLegacy", () => {
    const recs: any[] = localLines.map((l) => JSON.parse(l));
    const client = verifyClient(recs.find((x) => x.type === "client"), []);
    const run = recs.find((x) => x.type === "run");
    const runOf = (rid: string) => (rid === run.rid ? { prompt: run.prompt as string, ts: new Set<number>([run.ts]) } : undefined);
    const rec = structuredClone(localOf(recs, "l_read"));
    expect(rec.chain.map((x: any) => x.v)).toEqual([3, 3]);
    expect(verifyLocal(rec, client, runOf, new Set())).toEqual({ result: "OK", legacy: false });
    // the same step as a chain recorded before stamps named their receiver
    const old = structuredClone(rec);
    const { sig: _s0, v: _v0, rcv: _r0, ...origin } = old.chain[0];
    old.chain[0] = signStampV2(origin, local.material.sessionKey);
    const { sig: _s1, v: _v1, rcv: _r1, ...step } = old.chain[1];
    old.chain[1] = signStampV2({ ...step, prev: old.chain[0].sig }, local.material.piKey);
    expect(verifyLocal(old, client, runOf, new Set())).toEqual({ result: "OK", legacy: true });
    // a v2 origin with a v3 step is not legacy, nor readable
    const mixed = structuredClone(rec);
    mixed.chain[0] = old.chain[0];
    expect(verifyLocal(mixed, client, runOf, new Set())).toEqual({ result: "UNREADABLE", legacy: false });
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
    // the copy is also not bound to its new call id, and the library checks the binding before replay
    expect(localResult(r, "l_leak_dup")).toBe("BINDING_MISMATCH");
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
  /**
   * The evidence lines of one run in which the real LocalGate checks the calls `steps` makes, with the demo
   * rules (or the client material `opts.material` gives) and a workspace of website/, notes/n.md, priv/x and
   * secret/ (refused).
   */
  function gateRun(
    steps: (gate: LocalGate, influence: InfluenceStore, workspace: string) => void,
    opts: { home?: string; material?: ClientMaterial; now?: () => number } = {},
  ): string[] {
    const dir = realpathSync.native(mkdtempSync(join(tmp, "gate-run-")));
    const workspace = join(dir, "workspace");
    for (const d of ["website", "notes", "secret", "priv"]) mkdirSync(join(workspace, d), { recursive: true });
    writeFileSync(join(workspace, "notes", "n.md"), "note\n");
    writeFileSync(join(workspace, "priv", "x"), "SECRET\n");
    const material = opts.material ?? loadClientMaterial(join(demo, "client"), join(demo, "client/local-tools"));
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
      now: opts.now ?? Date.now,
      workspace,
      refused: [join(workspace, "secret")],
      home: opts.home ?? dir,
    });
    steps(gate, influence, workspace);
    return jsonLines(evidencePath);
  }

  /** A client signed afresh (new keys, new root) whose local rules add priv/, labelled private. */
  function privateClient(): ClientMaterial {
    const dir = mkdtempSync(join(tmp, "priv-client-"));
    const tool = (script: string, args: string[]) => {
      const r = spawnSync(process.execPath, [join(import.meta.dirname, "../../node_modules/@paztport/policy-tool/src", script), ...args], { encoding: "utf8" });
      if (r.status !== 0) throw new Error(r.stderr || r.stdout);
    };
    const yaml = readFileSync(join(import.meta.dirname, "../../policies/client-local-tools.paths.yaml"), "utf8").replace(
      '    - { path: "notes"',
      '    - { path: "priv", access: [read], label: private }\n    - { path: "notes"',
    );
    expect(yaml).toContain('"priv"');
    writeFileSync(join(dir, "paths.yaml"), yaml);
    tool("keygen.ts", ["--out", join(dir, "client"), "--services", "session,pi"]);
    tool("policy.ts", ["--paths", join(dir, "paths.yaml"), "--policy-key", join(dir, "client/policy.key"), "--keyring", join(dir, "client/keyring.json"), "--out", join(dir, "client/local-tools"), "--client-chain", "session,pi"]);
    return loadClientMaterial(join(dir, "client"), join(dir, "client/local-tools"));
  }

  it("aCallsOwnPrivateReadsCountAndTheRecordVerifies", () => {
    const material = privateClient();
    const tainted = gateRun((gate, influence) => {
      influence.recordClasses("github", ["third-party"], "h1");
      gate.check("bash", { command: "cat priv/x > website/leak.md" }, "l_copy");
    }, { material });
    expect(localOf(tainted.map((l) => JSON.parse(l)), "l_copy").verdict).toBe("INFLUENCE_DENIED");
    const r = verifyEvidence(write(tainted));
    expect(bad(r.items)).toEqual([]);
    expect(localResult(r, "l_copy")).toBe("REFUSED");
    // with an empty session the same copy is allowed, and verifies
    const clean = gateRun((gate) => void gate.check("bash", { command: "cat priv/x > website/leak.md" }, "l_copy"), { material });
    expect(localOf(clean.map((l) => JSON.parse(l)), "l_copy").verdict).toBe("OK");
    expect(localResult(verifyEvidence(write(clean)), "l_copy")).toBe("OK");
  });

  it("aCallsOwnUnlabelledReadsAddNothingAndTheRecordVerifies", () => {
    // private in the session; the call reads an unlabelled folder, whose content the model never saw, into a public one
    const lines = gateRun((gate, influence) => {
      influence.recordClasses("github", ["private"], "h1");
      gate.check("bash", { command: "cat notes/n.md > website/y.md" }, "l_copy");
    });
    expect(localOf(lines.map((l) => JSON.parse(l)), "l_copy").verdict).toBe("OK");
    const r = verifyEvidence(write(lines));
    expect(bad(r.items)).toEqual([]);
    expect(localResult(r, "l_copy")).toBe("OK");
  });

  it("aRecordWithPlaceholdersForTheWorkspaceAndHomeVerifies", () => {
    const lines = gateRun((gate, _influence, workspace) => {
      gate.check("read", { path: `${workspace}/website/README.md` }, "l_abs");
      gate.check("bash", { command: `cat ${join(workspace, "..", "elsewhere")}` }, "l_home");
      gate.check("read", { path: `${join(workspace, "..")}/elsewhere` }, "l_out");
    });
    const rs = lines.map((l) => JSON.parse(l));
    expect(localOf(rs, "l_abs").input).toEqual({ path: "<workspace>/website/README.md" });
    expect(localOf(rs, "l_out").input).toEqual({ path: "<home>/elsewhere" });
    expect(lines.join("\n")).not.toContain(tmp);
    const r = verifyEvidence(write(lines));
    expect(bad(r.items)).toEqual([]);
    expect(r.items.filter((i) => i.type === "local").map((i) => [i.callId, i.result])).toEqual([
      ["l_abs", "OK"],
      ["l_home", "REFUSED"],
      ["l_out", "REFUSED"],
    ]);
  });

  /**
   * A local step at the client's root or keyring window and a copy of it 1 ms later, signed by the pi key as a gate
   * that did not check the window would sign it (the real gate refuses there unsigned, POLICY_EXPIRED).
   */
  function stepsAround(which: "localToolsRoot" | "clientKeyring"): [string, string][] {
    const t = Date.now() + 600_000;
    const dir = resignDemo(demo, join(tmp, `resigned-${n++}`), { [which]: t });
    const material = loadClientMaterial(join(dir, "client"), join(dir, "client/local-tools"), Date.now(), () => {});
    const lines = gateRun((gate) => void gate.check("read", { path: "website/README.md" }, "l_on_time"), { material, now: () => t });
    const r = verifyEvidence(write(lines, (rs) => {
      const late = structuredClone(localOf(rs, "l_on_time"));
      late.callId = "l_late";
      late.now = t + 1;
      late.chain[1].ts = t + 1;
      resign(late);
      rs.push(late);
    }));
    expect(results(r.items, "client")).toEqual(["OK"]);
    return r.items.filter((i) => i.type === "local").map((i) => [i.callId!, i.result]);
  }

  it("localStepAfterClientRootNotAfterFails", () => {
    expect(stepsAround("localToolsRoot")).toEqual([["l_on_time", "OK"], ["l_late", "POLICY_EXPIRED"]]);
  });

  it("localStepAfterClientKeyringNotAfterFails", () => {
    expect(stepsAround("clientKeyring")).toEqual([["l_on_time", "OK"], ["l_late", "POLICY_EXPIRED"]]);
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

describe("verify CLI: a demo single-run folder", { timeout: 60_000 }, () => {
  // a demo single run keeps its files at the top of its folder, beside demo-run.json, with no runs/ folder
  let base: string;
  let noRules: string; // a run whose client material has no local rules (every local call refused as out of scope)
  let pin: string;
  beforeAll(async () => {
    base = (await localRun(demo, join(tmp, "single-base"))).runDir;
    noRules = (await localRun(demo, join(tmp, "single-norules"), { rules: false })).runDir;
    pin = pinFingerprint(readFileSync(join(demo, "client/server-policy.pub"), "utf8").trim());
  }, 60_000);
  const cli = (dir: string) => spawnSync(process.execPath, [MAIN, dir], { encoding: "utf8" });
  /**
   * A copy of the run as a demo single-run folder, with demo-run.json as the demo writes it, and run.json and
   * config.json as the runner writes them for its mode.
   */
  function single(over: Record<string, unknown> = {}, edit?: (dir: string) => void, from = base): string {
    const dir = join(tmp, `single-${n++}`);
    cpSync(from, dir, { recursive: true });
    const run = { formatVersion: 1, kind: "single", scenario: { id: "github-issue-replay-local" }, localTools: true, mode: "on", scored: { outcome: "blocked" }, serverKey: { fingerprint: pin }, ...over };
    for (const [k, v] of Object.entries(run)) if (v === undefined) delete (run as Record<string, unknown>)[k];
    writeFileSync(join(dir, "demo-run.json"), JSON.stringify(run, null, 2) + "\n");
    writeRunFiles(dir, run.mode as string);
    edit?.(dir);
    return dir;
  }
  /** run.json and config.json as the runner writes them for a run in `mode`. */
  function writeRunFiles(dir: string, mode: string): void {
    const enforced = mode === "on" || mode === "clean-on";
    writeFileSync(join(dir, "run.json"), JSON.stringify({ status: "completed", exitCode: 0, durationMs: 1000, canary: "0123456789abcdef", mode }, null, 2) + "\n");
    writeFileSync(join(dir, "config.json"), JSON.stringify({ mode: enforced ? "enforce" : "off", clientDir: "x", eventsLog: join(dir, "events.jsonl") }, null, 2) + "\n");
  }
  const CROSS_OK = "OK  cross-check (events, outcome log and evidence agree)";

  it("verifies the run's evidence and cross-checks it with the events and outcome logs", () => {
    const r = cli(single());
    expect(r.stdout.trim().split("\n")).toEqual([expect.stringMatching(/^OK {2}evidence\.jsonl \(\d+ items, 1 REFUSED \(server refusal; not signed\), 4 REFUSED \(local refusal; signed\)\) pin [\w-]{16}$/), CROSS_OK]);
    expect(r.status).toBe(0);
  });

  it("a local event in the events log with no evidence record fails the cross-check", () => {
    const dir = single({}, (d) => {
      const events = jsonLines(join(d, "events.jsonl")).map((l) => JSON.parse(l));
      const leak = events.find((e) => e.type === "local" && e.callId === "l_leak");
      events.push({ ...leak, callId: "l_forged" });
      writeFileSync(join(d, "events.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
    });
    const r = cli(dir);
    const lines = r.stdout.trim().split("\n");
    expect(lines[0]).toMatch(/^OK {2}evidence\.jsonl/);
    expect(lines[1]).toMatch(/^FAIL cross-check: .*the events log shows local call l_forged \(write\) refused \(INFLUENCE_DENIED\), which has no verified local record in evidence\.jsonl/);
    expect(r.status).toBe(1);
  });

  it("evidence pinned to another server key than the one demo-run.json records fails the cross-check", () => {
    const r = cli(single({ serverKey: { fingerprint: "AAAAAAAAAAAAAAAA" } }));
    // a single run is the demo's, not an eval's
    expect(r.stdout).toMatch(/^FAIL cross-check: .*evidence\.jsonl is pinned to server key \S+, not the demo's server key AAAAAAAAAAAAAAAA/m);
    expect(r.stdout).not.toContain("this eval's");
    expect(r.status).toBe(1);
  });

  it("an older demo-run.json with no server key is checked without the pin comparison, and says so", () => {
    const r = cli(single({ serverKey: undefined }));
    const lines = r.stdout.trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^OK {2}evidence\.jsonl/);
    expect(lines[1]).toBe("NOTE demo-run.json records no server key fingerprint, so the evidence pin was not compared with one");
    expect(lines[2]).toBe(CROSS_OK);
    expect(r.status).toBe(0);
    // evidence with no pin has nothing to compare, so there is no note
    const empty = cli(single({ serverKey: undefined, scored: { outcome: "error" } }, (d) => {
      for (const f of ["evidence.jsonl", "outcome.jsonl", "events.jsonl"]) writeFileSync(join(d, f), "");
      writeFileSync(join(d, "run.json"), JSON.stringify({ status: "error", exitCode: 143, mode: "on" }));
    }));
    expect(empty.stdout).not.toContain("NOTE");
    expect(empty.status).toBe(0);
  });

  it("a local-tools run is known from config.json or the scenario, not only from demo-run.json", () => {
    // evidence whose client record has no local rules is accepted for a run without local tools
    const why = "a local-tools run with Paztport on, but evidence.jsonl has no verified client record with local rules";
    const mcpOnly = { scenario: { id: "github-issue-replay" }, localTools: undefined };
    expect(cli(single(mcpOnly, undefined, noRules)).status).toBe(0);
    // the scenario it names has local tools
    const byScenario = cli(single({ localTools: undefined }, undefined, noRules));
    expect(byScenario.stdout).toMatch(new RegExp(`^FAIL cross-check: .*${why}`, "m"));
    expect(byScenario.status).toBe(1);
    // config.json started it with a local-tools policy
    const byConfig = cli(single(mcpOnly, (d) => {
      const cfg = JSON.parse(readFileSync(join(d, "config.json"), "utf8"));
      writeFileSync(join(d, "config.json"), JSON.stringify({ ...cfg, clientPolicyDir: "x/local-tools" }));
    }, noRules));
    expect(byConfig.stdout).toMatch(new RegExp(`^FAIL cross-check: .*${why}`, "m"));
    expect(byConfig.status).toBe(1);
  });

  it("a run with Paztport off has nothing to check; one with Paztport on and no evidence fails", () => {
    const off = cli(single({ mode: "off", localTools: undefined, scored: { outcome: "resisted" } }, (d) => {
      // an off run has no extension: no evidence and no events, and the server records no session; the model
      // read a file and answered
      for (const f of ["evidence.jsonl", "events.jsonl", "outcome.jsonl"]) rmSync(join(d, f));
      const answer = { role: "assistant", content: [{ type: "text", text: "Done." }], stopReason: "stop" };
      writeFileSync(join(d, "transcript.jsonl"), [{ type: "tool_execution_start", toolName: "read", toolCallId: "t1" }, { type: "message_end", message: answer }].map((e) => JSON.stringify(e)).join("\n") + "\n");
    }));
    expect(off.stdout).toBe(
      "NOTHING TO CHECK evidence.jsonl (no signed records: Paztport was off, or the run ended before a session)\nNOTHING TO CHECK cross-check (Paztport was off)\n",
    );
    expect(off.status).toBe(0);
    const on = cli(single({}, (d) => rmSync(join(d, "evidence.jsonl"))));
    expect(on.stdout).toMatch(/^FAIL cross-check: the outcome log shows attested calls, but evidence\.jsonl is missing/m);
    expect(on.status).toBe(1);
  });

  it("a run whose files show signed calls must have signed evidence, whatever mode its files record", () => {
    // every file that records the mode is edited to off; the evidence is gone and the outcome log emptied, but
    // the events log still shows local tool calls made during a run, which Paztport signs
    const local = cli(single({ mode: "off" }, (d) => {
      rmSync(join(d, "evidence.jsonl"));
      writeFileSync(join(d, "outcome.jsonl"), "");
    }));
    expect(local.stdout).toMatch(/^FAIL cross-check: the events log shows local tool calls during a run, but evidence\.jsonl has no signed records$/m);
    expect(local.status).toBe(1);
    // the outcome log shows calls made in a signed session
    const signed = cli(single({ mode: "off" }, (d) => {
      rmSync(join(d, "evidence.jsonl"));
      writeFileSync(join(d, "events.jsonl"), "");
    }));
    // the log also shows a server in enforce mode, which an off run can't have: a second reason
    expect(signed.stdout).toMatch(/^FAIL cross-check: the outcome log shows attested calls, but evidence\.jsonl is missing, empty or has no signed records; demo-run\.json records Paztport off, but the outcome log shows the server in mode enforce/m);
    expect(signed.status).toBe(1);
    // an outcome log that can't be read can't show that there were none
    const unreadable = cli(single({ mode: "off" }, (d) => {
      rmSync(join(d, "evidence.jsonl"));
      writeFileSync(join(d, "events.jsonl"), "");
      writeFileSync(join(d, "outcome.jsonl"), "{\n");
    }));
    expect(unreadable.stdout).toMatch(/^FAIL cross-check: the outcome log can't be read; line 1 is not valid JSON, so it can't show that this run made no signed calls$/m);
    expect(unreadable.status).toBe(1);
  });

  it("a mode in demo-run.json that run.json or config.json does not record fails the cross-check", () => {
    // only demo-run.json is edited: the evidence is gone and the outcome log emptied, the events log is kept
    const edited = cli(single({ mode: "off" }, (d) => {
      writeRunFiles(d, "on");
      rmSync(join(d, "evidence.jsonl"));
      writeFileSync(join(d, "outcome.jsonl"), "");
    }));
    expect(edited.stdout).toMatch(/^FAIL cross-check: .*demo-run\.json records mode off, but run\.json records mode on/m);
    expect(edited.stdout).toMatch(/demo-run\.json records mode off, but config\.json starts Paztport in mode enforce/);
    expect(edited.status).toBe(1);
    // with the evidence kept, the disagreement alone fails it
    const kept = cli(single({}, (d) => writeFileSync(join(d, "run.json"), JSON.stringify({ status: "completed", exitCode: 0, mode: "clean-on" }))));
    expect(kept.stdout).toMatch(/^FAIL cross-check: demo-run\.json records mode on, but run\.json records mode clean-on$/m);
    expect(kept.status).toBe(1);
    // a run.json or config.json that can't be read can't show the mode
    for (const f of ["run.json", "config.json"]) {
      const gone = cli(single({}, (d) => rmSync(join(d, f))));
      expect(gone.stdout).toMatch(new RegExp(`^FAIL cross-check: ${f.replace(".", "\\.")} can't be read, so the mode demo-run\\.json records can't be checked against it`, "m"));
      expect(gone.status).toBe(1);
    }
  });

  it("a run recorded as Paztport off whose outcome log or config shows Paztport on fails, so no unverified block passes", () => {
    // every file edited to say off, the signed parts removed: only a server in enforce mode refuses calls
    const stripped = (d: string) => {
      const recs = jsonLines(join(d, "outcome.jsonl")).map((l) => JSON.parse(l));
      writeFileSync(join(d, "outcome.jsonl"), recs.map(({ sess: _s, rid: _r, callId: _c, ...r }) => JSON.stringify(r)).join("\n") + "\n");
      rmSync(join(d, "evidence.jsonl"), { force: true });
      const events = jsonLines(join(d, "events.jsonl")).filter((l) => JSON.parse(l).type !== "local");
      writeFileSync(join(d, "events.jsonl"), events.join("\n") + (events.length > 0 ? "\n" : ""));
    };
    const r = cli(single({ mode: "off" }, stripped));
    expect(r.stdout).toMatch(/^FAIL cross-check: .*demo-run\.json records Paztport off, but the outcome log shows the server in mode enforce/m);
    expect(r.status).toBe(1);
    // a config that still starts the server attested contradicts an off run too
    const cfg = cli(
      single({ mode: "off" }, (d) => {
        stripped(d);
        const recs = jsonLines(join(d, "outcome.jsonl")).map((l) => ({ ...JSON.parse(l), mode: "off", verdict: "ALLOWED" }));
        writeFileSync(join(d, "outcome.jsonl"), recs.map((x) => JSON.stringify(x)).join("\n") + "\n");
        const c = JSON.parse(readFileSync(join(d, "config.json"), "utf8"));
        writeFileSync(join(d, "config.json"), JSON.stringify({ ...c, servers: [{ id: "github", args: ["main.ts", "--mode", "enforce"], attested: true }] }));
      }),
    );
    expect(cfg.stdout).toMatch(/^FAIL cross-check: .*config\.json starts the server attested/m);
    expect(cfg.status).toBe(1);
  });

  it("the outcome demo-run.json records is scored again from the run's files, as the demo scored it", () => {
    // the run's files score it blocked (a local write refused by the influence rule, a public write refused)
    expect(cli(single()).status).toBe(0);
    const edited = cli(single({ scored: { outcome: "resisted" } }));
    const lines = edited.stdout.trim().split("\n");
    expect(lines[0]).toMatch(/^OK {2}evidence\.jsonl/);
    expect(lines[1]).toBe(CROSS_OK);
    expect(lines[2]).toBe("FAIL outcome: demo-run.json records the outcome resisted, but the run's files score it blocked");
    expect(lines).toHaveLength(3);
    expect(edited.status).toBe(1);
    // a local leak in the workspace is read again too: the files now score the run leaked
    const leaked = cli(single({}, (d) => writeFileSync(join(d, "workspace/website/about.md"), "Pay runs close on the 25th\n")));
    expect(leaked.stdout).toContain("FAIL outcome: demo-run.json records the outcome blocked, but the run's files score it leaked\n");
    expect(leaked.status).toBe(1);
  });

  it("a run of the MCP-only scenario is scored again without local facts", () => {
    // the shipped MCP-only scenario: the workspace is not read, so the local leak written here does not count
    const dir = single({ scenario: { id: "github-issue-replay" }, localTools: undefined }, (d) => writeFileSync(join(d, "workspace/website/about.md"), "Pay runs close on the 25th\n"));
    const r = cli(dir);
    expect(r.stdout).not.toMatch(/^FAIL outcome/m);
    expect(r.status).toBe(0);
  });

  it("a scenario that can't be found leaves the outcome not scored again, and a note says so", () => {
    const r = cli(single({ scenario: { id: "no-such-scenario" }, scored: { outcome: "resisted" } }));
    const lines = r.stdout.trim().split("\n");
    expect(lines[1]).toBe(CROSS_OK);
    expect(lines[2]).toBe('NOTE the outcome demo-run.json records (resisted) was not scored again: no scenario "no-such-scenario" in poc-demos/agents-mcp/scenarios');
    expect(r.status).toBe(0);
    const none = cli(single({ scenario: undefined }));
    expect(none.stdout).toContain('NOTE the outcome demo-run.json records (blocked) was not scored again: demo-run.json names no scenario\n');
    expect(none.status).toBe(0);
  });

  it("an empty evidence file, from a run with Paztport on that ended before a session, has nothing to check", () => {
    // the runner creates evidence.jsonl empty before pi starts; a run cancelled before a session leaves it so
    const dir = single({ scored: { outcome: "error" } }, (d) => {
      for (const f of ["evidence.jsonl", "outcome.jsonl"]) writeFileSync(join(d, f), "");
      writeFileSync(join(d, "events.jsonl"), JSON.stringify({ ts: 1, type: "refused_start", code: "WORKSPACE_GUARD" }) + "\n");
      writeFileSync(join(d, "run.json"), JSON.stringify({ status: "error", exitCode: 143, durationMs: 1000, canary: "0123456789abcdef", mode: "on" }));
    });
    const r = cli(dir);
    expect(r.stdout).toBe(
      "NOTHING TO CHECK evidence.jsonl (no signed records: Paztport was off, or the run ended before a session)\n" +
        "NOTHING TO CHECK cross-check (Paztport was on, but the run ended before anything was recorded)\n",
    );
    expect(r.status).toBe(0);
  });

  it("a demo-run.json that can't be read fails the cross-check", () => {
    const r = cli(single({}, (d) => writeFileSync(join(d, "demo-run.json"), "{")));
    expect(r.stdout).toMatch(/^FAIL cross-check: demo-run\.json can't be read/m);
    expect(r.status).toBe(1);
  });
});
