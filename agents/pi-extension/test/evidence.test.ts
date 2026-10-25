// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { ExtensionMode, ServerSpec } from "../src/config.ts";
import { ServerConnection } from "../src/connection.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceLog, type EvidenceRecord } from "../src/evidence.ts";
import paztport from "../src/index.ts";
import { InfluenceStore } from "../src/influence.ts";
import { loadClientMaterial, type ClientMaterial } from "../src/keys.ts";
import { RunState } from "../src/runs.ts";
import { CANARY, DOCS, githubArgs, records, setupDemo, STUB } from "./helpers/demo.ts";

let tmp: string;
let demo: string;
let material: ClientMaterial;
let n = 0;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-evid-"));
  demo = setupDemo(tmp);
  material = loadClientMaterial(join(demo, "client"));
});
const opened: ServerConnection[] = [];
afterEach(async () => {
  await Promise.all(opened.splice(0).map((c) => c.close()));
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Ctx = { mode: ExtensionMode; influence: InfluenceStore; runs: RunState; eventsPath: string; evidencePath: string; now?: () => number };

function ctx(mode: ExtensionMode = "enforce", now?: () => number): Ctx {
  return { mode, influence: new InfluenceStore(), runs: new RunState(), eventsPath: join(tmp, `events-${n++}.jsonl`), evidencePath: join(tmp, `evidence-${n++}.jsonl`), now };
}

async function connect(c: Ctx, spec: ServerSpec, withEvidence = true): Promise<ServerConnection> {
  const conn = new ServerConnection(
    spec,
    c.mode,
    material,
    c.influence,
    c.runs,
    new EventLog(c.eventsPath),
    c.now,
    ...(withEvidence ? [new EvidenceLog(c.evidencePath)] : []),
  );
  opened.push(conn);
  await conn.connect();
  return conn;
}

function github(c: Ctx, serverMode: "enforce" | "audit" | "off" = "enforce", spec: Partial<ServerSpec> = {}, withEvidence = true): Promise<ServerConnection> {
  return connect(
    c,
    {
      id: "github",
      command: process.execPath,
      args: githubArgs(demo, serverMode, join(tmp, `outcome-${n++}.jsonl`)),
      attested: true,
      pin: join(demo, "client/server-policy.pub"),
      ...spec,
    },
    withEvidence,
  );
}

let seq = 0;
const call = (conn: ServerConnection, tool: string, args: Record<string, unknown>) => conn.call(tool, args, `toolu_${seq++}`);

async function scenarioA(conn: ServerConnection): Promise<void> {
  await call(conn, "list_issues", { owner: "acme", repo: "website" });
  await call(conn, "search_repositories", { query: "user:acme" });
  await call(conn, "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" });
  await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "leak" });
}

const evidence = (c: Ctx): EvidenceRecord[] => records(c.evidencePath) as unknown as EvidenceRecord[];
const ofType = <T extends EvidenceRecord["type"]>(rs: EvidenceRecord[], t: T): Extract<EvidenceRecord, { type: T }>[] =>
  rs.filter((r): r is Extract<EvidenceRecord, { type: T }> => r.type === t);

describe("evidence file", { timeout: 30_000 }, () => {
  it("evidenceHasWhatVerifyNeeds", async () => {
    let t = Date.now();
    const c = ctx("enforce", () => (t += 1));
    const conn = await github(c);
    c.runs.start("fix the typo", Date.now());
    const rid = c.runs.current()!.rid;
    await scenarioA(conn);
    const rs = evidence(c);
    expect(rs.every((r) => r.v === 1)).toBe(true);

    const sessions = ofType(rs, "session");
    expect(sessions).toHaveLength(1);
    const s = sessions[0]!;
    expect(s.server).toBe("github");
    expect(s.status).toBe("attested");
    expect(s.pin).toBe(readFileSync(join(demo, "client/server-policy.pub"), "utf8").trim());
    expect(s.request).toMatchObject({
      clientRoot: material.signedRoot,
      clientPolicyKey: material.policyPublicKey,
      clientKeyring: material.keyring,
    });
    expect(typeof s.request.nonce).toBe("string");
    expect(s.reply).toMatchObject({ status: "attested", serverPolicyKey: s.pin, sess: expect.any(String), sig: expect.any(String) });

    const calls = ofType(rs, "call");
    const responses = ofType(rs, "response");
    expect(calls.map((x) => x.tool)).toEqual(["list_issues", "search_repositories", "get_file_contents", "create_branch"]);
    expect(responses.map((x) => x.callId)).toEqual(calls.map((x) => x.callId));
    for (const x of calls) {
      expect(x.rid).toBe(rid);
      expect(x.server).toBe("github");
      expect(x.params.name).toBe(x.tool);
      expect(x.params._meta).toHaveProperty("paztport/chain");
      expect(x.params._meta).toHaveProperty("paztport/proof");
      expect(x.params._meta).toHaveProperty("paztport/influence");
      const chain = x.params._meta["paztport/chain"] as { svc: string; ts: number }[];
      expect(chain[chain.length - 1]!.svc).toBe("pi");
      expect(x.now).toBe(chain[chain.length - 1]!.ts); // the timestamp used for the stamp
    }
    expect(calls[2]!.params.arguments).toEqual({ owner: "acme", repo: "payroll-notes", path: "README.md" });
    for (const x of responses) {
      expect(x.rid).toBe(rid);
      expect(x.result).toMatchObject({ content: expect.any(Array) });
      expect(typeof x.now).toBe("number");
    }
    // verification time comes after the stamp time of the same call
    responses.forEach((r, i) => expect(r.now).toBeGreaterThan(calls[i]!.now));
    // verified results keep their _meta; the refusal on the write carries the verdict
    expect((responses[0]!.result as { _meta: object })._meta).toBeDefined();
    expect(JSON.stringify(responses[3]!.result)).toContain("INFLUENCE_DENIED");
    // file order: session, then each call before its response
    expect(rs.map((r) => r.type)).toEqual(["session", "call", "response", "call", "response", "call", "response", "call", "response"]);
  });

  it("evidenceHasNoPrivateKeys", async () => {
    const c = ctx();
    const conn = await github(c);
    c.runs.start("fix the typo", Date.now());
    await scenarioA(conn);
    const text = readFileSync(c.evidencePath, "utf8");
    expect(text.length).toBeGreaterThan(0);
    let keys = 0;
    for (const side of ["client", "server"]) {
      const dir = join(demo, side);
      for (const f of readdirSync(dir).filter((f) => f.endsWith(".key"))) {
        keys++;
        expect(text).not.toContain(readFileSync(join(dir, f), "utf8").trim());
      }
    }
    expect(keys).toBeGreaterThan(0);
    // the session key is the client's private signing key for origin stamps
    expect(text).not.toContain(material.sessionKey);
    expect(text).not.toContain(material.piKey);
  });

  it("noEvidenceWithoutPath", async () => {
    const c = ctx();
    const conn = await github(c, "enforce", {}, false);
    c.runs.start("fix the typo", Date.now());
    await scenarioA(conn);
    expect(existsSync(c.evidencePath)).toBe(false);
    expect(() => new EvidenceLog(undefined).write({ v: 1, type: "run", rid: "r", ts: 1, prompt: "p" })).not.toThrow();
  });

  it("noPathIsNoopAndBadPathThrowsAtConstruction", () => {
    expect(() => new EvidenceLog(join(tmp, "missing-dir", "e.jsonl"))).toThrow();
  });

  it("sessionRecordedForFailedPin", async () => {
    const c = ctx();
    const wrong = join(tmp, `wrong-pin-${n++}.pub`);
    writeFileSync(wrong, "AAAA\n");
    await github(c, "enforce", { pin: wrong });
    const rs = evidence(c);
    // the failed attempt, then the best-effort replacement session without a client root
    const sessions = ofType(rs, "session");
    expect(sessions).toHaveLength(2);
    expect(sessions[0]!.status).toBe("unsafe");
    expect(sessions[0]!.reason).toBe("PIN_MISMATCH");
    expect(sessions[0]!.pin).toBe("AAAA");
    expect(sessions[0]!.request.clientRoot).not.toBeNull();
    expect(sessions[0]!.reply).toMatchObject({ status: "attested" });
    expect(sessions[1]!.request.clientRoot).toBeNull();
    expect(sessions[1]!.request.nonce).not.toBe(sessions[0]!.request.nonce);
    expect(sessions[1]!.status).toBe("unsafe");
    expect(sessions[1]!.reason).toBe("PIN_MISMATCH");
    expect(ofType(rs, "call")).toEqual([]);
  });

  it("noRootSessionRecordsNullRoot", async () => {
    const c = ctx("no-root");
    const conn = await github(c);
    c.runs.start("fix the typo", Date.now());
    await call(conn, "list_issues", { owner: "acme", repo: "website" });
    const rs = evidence(c);
    const sessions = ofType(rs, "session");
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.request.clientRoot).toBeNull();
    expect(sessions[0]!.status).toBe("unsafe");
    expect(sessions[0]!.reason).toBe("UNSAFE");
    // an unsafe connection sends plain calls: nothing to re-verify
    expect(ofType(rs, "call")).toEqual([]);
    expect(ofType(rs, "response")).toEqual([]);
  });

  it("unattestedAndOffRecordNoSession", async () => {
    const c = ctx();
    const conn = await connect(c, { id: "docs", command: process.execPath, args: [DOCS], attested: false });
    c.runs.start("fix the typo", Date.now());
    await call(conn, "list_docs", {}).catch(() => {});
    const off = ctx("off");
    const offConn = await github(off);
    off.runs.start("fix the typo", Date.now());
    await call(offConn, "list_issues", { owner: "acme", repo: "website" });
    expect(existsSync(c.evidencePath) ? evidence(c) : []).toEqual([]);
    expect(existsSync(off.evidencePath) ? evidence(off) : []).toEqual([]);
  });

  it("methodNotFoundIsRecordedWithoutReply", async () => {
    const c = ctx();
    await connect(c, { id: "stub", command: process.execPath, args: [STUB], attested: true, pin: join(demo, "client/server-policy.pub") });
    const sessions = ofType(evidence(c), "session");
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.status).toBe("unsafe");
    expect(sessions[0]!.reason).toBe("METHOD_NOT_FOUND");
    expect(sessions[0]!.reply).toBeNull();
  });

  it("failedHandshakesRecordBothRequests", async () => {
    for (const [mode, reply, reason] of [["malformed", {}, "MALFORMED_REPLY"], ["error", null, "HANDSHAKE_ERROR"]] as const) {
      const c = ctx();
      await connect(c, { id: "stub", command: process.execPath, args: [STUB, "--session-reply", mode], attested: true, pin: join(demo, "client/server-policy.pub") });
      const sessions = ofType(evidence(c), "session");
      expect(sessions.map((x) => x.reason)).toEqual([reason, reason]);
      expect(sessions[0]!.reply).toEqual(reply);
      expect(sessions[0]!.request.clientRoot).not.toBeNull();
      expect(sessions[1]!.request.clientRoot).toBeNull();
    }
  });

  it("localRefusalsWriteNoCallRecord", async () => {
    const c = ctx();
    const conn = await github(c);
    await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" }); // no run: nothing sent
    const rs = evidence(c);
    expect(rs.map((r) => r.type)).toEqual(["session"]);
  });

  it("eventsLogUnchanged", async () => {
    const c = ctx();
    const conn = await github(c);
    c.runs.start("fix the typo", Date.now());
    await scenarioA(conn);
    const text = readFileSync(c.eventsPath, "utf8");
    expect(text).not.toContain("paztport/");
    expect(text.toLowerCase()).not.toContain(CANARY);
    for (const e of records(c.eventsPath)) {
      expect(Object.keys(e).filter((k) => !["ts", "type", "server", "tool", "callId", "rid", "session", "status", "reason", "verdict", "verify", "labels", "isError", "classes", "code", "rpcCode"].includes(k))).toEqual([]);
    }
  });
});

describe("extension wiring", { timeout: 30_000 }, () => {
  function fake(flags: Record<string, string>) {
    const handlers = new Map<string, ((e: Record<string, unknown>, c: ExtensionContext) => unknown)[]>();
    const workspace = join(tmp, `ws-${n++}`);
    mkdirSync(workspace);
    const api = {
      registerFlag: () => {},
      getFlag: (k: string) => flags[k],
      registerTool: () => {},
      on: (t: string, h: (e: Record<string, unknown>, c: ExtensionContext) => unknown) => void handlers.set(t, [...(handlers.get(t) ?? []), h]),
    } as unknown as ExtensionAPI;
    const cx = { cwd: workspace, sessionManager: { getBranch: () => [], getEntry: () => undefined, getHeader: () => null, getSessionDir: () => "" } } as unknown as ExtensionContext;
    const emit = async (type: string, e: Record<string, unknown> = {}) => {
      for (const h of handlers.get(type) ?? []) await h({ type, ...e }, cx);
    };
    paztport(api);
    return { emit };
  }

  function config(extra: Record<string, unknown>): string {
    const path = join(tmp, `config-${n++}.json`);
    writeFileSync(
      path,
      JSON.stringify({
        mode: "enforce",
        clientDir: join(demo, "client"),
        servers: [{ id: "github", command: process.execPath, args: githubArgs(demo, "enforce", join(tmp, `outcome-${n++}.jsonl`)), attested: true }],
        ...extra,
      }),
    );
    return path;
  }

  it("writesRunAndSessionRecordsWhenConfigured", async () => {
    const evidencePath = join(tmp, `ext-evidence-${n++}.jsonl`);
    const eventsPath = join(tmp, `ext-events-${n++}.jsonl`);
    const pi = fake({ "paztport-config": config({ evidenceLog: evidencePath, eventsLog: eventsPath }) });
    try {
      await pi.emit("session_start", { reason: "startup" });
      const before = Date.now();
      await pi.emit("before_agent_start", { messageType: "user", prompt: "fix the typo", systemPrompt: "" });
      const rs = records(evidencePath) as unknown as EvidenceRecord[];
      // the client mesh first (enforce mode), then the server session, then the run
      expect(rs.map((r) => r.type)).toEqual(["client", "session", "run"]);
      const client = ofType(rs, "client")[0]!;
      expect(client).toEqual({
        v: 1,
        type: "client",
        keyring: material.keyring,
        policyPublicKey: material.policyPublicKey,
        signedRoot: material.signedRoot,
        rules: null,
        rulesProof: null,
      });
      const run = ofType(rs, "run")[0]!;
      expect(run.prompt).toBe("fix the typo");
      expect(run.rid).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(run.ts).toBeGreaterThanOrEqual(before);
      expect(readFileSync(eventsPath, "utf8")).not.toContain("fix the typo");
    } finally {
      await pi.emit("session_shutdown", { reason: "quit" });
    }
  });

  it("noEvidenceFileWithoutEvidenceLog", async () => {
    const pi = fake({ "paztport-config": config({}) });
    const before = readdirSync(tmp).filter((f) => f.includes("evidence"));
    try {
      await pi.emit("session_start", { reason: "startup" });
      await pi.emit("before_agent_start", { messageType: "user", prompt: "fix the typo", systemPrompt: "" });
    } finally {
      await pi.emit("session_shutdown", { reason: "quit" });
    }
    expect(readdirSync(tmp).filter((f) => f.includes("evidence"))).toEqual(before);
  });
});
