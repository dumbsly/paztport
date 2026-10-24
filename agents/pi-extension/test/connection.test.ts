// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair } from "@paztport/path-attest";
import type { ExtensionMode, ServerSpec } from "../src/config.ts";
import { ServerConnection, type CallOutcome } from "../src/connection.ts";
import { EventLog } from "../src/events.ts";
import { InfluenceStore } from "../src/influence.ts";
import { loadClientMaterial, type ClientMaterial } from "../src/keys.ts";
import { RunState } from "../src/runs.ts";

const MOCK = join(import.meta.dirname, "../../mock-github-mcp/src");
const MAIN = join(MOCK, "main.ts");
const DOCS = join(MOCK, "docs-main.ts");
const SETUP = join(import.meta.dirname, "../../scripts/setup-demo.ts");
const CANARY = "c0ffee";
const CALL_ID = /^[A-Za-z0-9_-]{1,128}$/;
const FIXED_README = "# Acme website\n\nWelcome to the Acme website.\n\nThis repository holds the public marketing site.\n";
const LEAK = `Notes copied from payroll: Reference: ${CANARY}\n`;

let tmp: string;
let demo: string;
let material: ClientMaterial;
let n = 0;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-conn-"));
  demo = join(tmp, "demo");
  const r = spawnSync(process.execPath, [SETUP, "--out", demo], { encoding: "utf8" });
  expect(r.status, r.stderr).toBe(0);
  material = loadClientMaterial(join(demo, "client"));
});
const opened: ServerConnection[] = [];
afterEach(async () => {
  await Promise.all(opened.splice(0).map((c) => c.close()));
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Ctx = {
  mode: ExtensionMode;
  influence: InfluenceStore;
  runs: RunState;
  events: EventLog;
  eventsPath: string;
  material: ClientMaterial;
  now?: () => number;
};

function ctx(mode: ExtensionMode = "enforce", m: ClientMaterial = material, now?: () => number): Ctx {
  const eventsPath = join(tmp, `events-${n++}.jsonl`);
  return { mode, influence: new InfluenceStore(), runs: new RunState(), events: new EventLog(eventsPath), eventsPath, material: m, now };
}

async function connect(c: Ctx, spec: ServerSpec): Promise<ServerConnection> {
  const conn = new ServerConnection(spec, c.mode, c.material, c.influence, c.runs, c.events, c.now);
  opened.push(conn);
  await conn.connect();
  return conn;
}

async function github(
  c: Ctx,
  serverMode: "enforce" | "audit" | "off" = "enforce",
  spec: Partial<ServerSpec> = {},
): Promise<{ conn: ServerConnection; log: string }> {
  const log = join(tmp, `outcome-${n++}.jsonl`);
  const args = [MAIN, "--mode", serverMode, "--config", join(demo, "server"), "--outcome-log", log, "--canary", CANARY];
  const conn = await connect(c, {
    id: "github",
    command: process.execPath,
    args,
    attested: true,
    pin: join(demo, "client/server-policy.pub"),
    ...spec,
  });
  return { conn, log };
}

function docs(c: Ctx, attested = false): Promise<ServerConnection> {
  return connect(c, { id: "docs", command: process.execPath, args: [DOCS], attested });
}

const records = (path: string): Record<string, any>[] =>
  readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const events = (c: Ctx): Record<string, any>[] => records(c.eventsPath);

let seq = 0;
const call = (conn: ServerConnection, tool: string, args: Record<string, unknown>): Promise<CallOutcome> =>
  conn.call(tool, args, `toolu_${seq++}`);

/** The scenario A reads, then the first public write. */
async function leakUntilBranch(conn: ServerConnection): Promise<CallOutcome[]> {
  return [
    await call(conn, "list_issues", { owner: "acme", repo: "website" }),
    await call(conn, "search_repositories", { query: "user:acme" }),
    await call(conn, "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
    await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "leak" }),
  ];
}

describe("ServerConnection", { timeout: 30_000 }, () => {
  it("attestedHandshake", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    expect(conn.status()).toBe("attested");
    expect(conn.tools().map((t) => t.name)).toContain("create_branch");
    expect(conn.tools()).toHaveLength(9);
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "session", server: "github", status: "attested" }));
    c.runs.start("fix the typo", Date.now());
    const out = await conn.call("list_issues", { owner: "acme", repo: "website" }, "toolu_A1");
    expect(out.isError).toBe(false);
    expect(out.text).toContain("Typo in README");
    expect(out.details).toMatchObject({ server: "github", callId: "toolu_A1", rid: c.runs.current()!.rid, verify: "OK", labels: ["third-party"], session: "attested" });
    expect(out.details.verdict).toBeUndefined();
    expect(out.details.influence["third-party"]).toBe(1);
    expect(c.influence.entries()).toEqual([expect.objectContaining({ cls: "third-party", src: "server:github" })]);
    expect(records(log)).toEqual([expect.objectContaining({ tool: "list_issues", verdict: "ALLOWED", rid: c.runs.current()!.rid, callId: "toolu_A1" })]);
  });

  it("scenarioA_leakRefusedByServer", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const [issues, search, payroll, branch] = await leakUntilBranch(conn);
    for (const o of [issues, search, payroll]) {
      expect(o!.isError).toBe(false);
      expect(o!.details.verify).toBe("OK");
    }
    expect(payroll!.text).toContain(CANARY);
    expect(branch!.isError).toBe(true);
    expect(branch!.details.verdict).toBe("INFLUENCE_DENIED");
    expect(branch!.text).toContain("INFLUENCE_DENIED");
    const classes = c.influence.classes();
    expect(classes.has("third-party") && classes.has("private")).toBe(true);
    expect(records(log).at(-1)).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED", audit: false });
  });

  it("legitFixAllowed", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const reads = [
      await call(conn, "list_issues", { owner: "acme", repo: "website" }),
      await call(conn, "get_file_contents", { owner: "acme", repo: "website", path: "README.md" }),
    ];
    const writes = [
      await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "fix" }),
      await call(conn, "create_or_update_file", { owner: "acme", repo: "website", path: "README.md", content: FIXED_README, message: "Fix typo", branch: "fix" }),
      await call(conn, "create_pull_request", { owner: "acme", repo: "website", title: "Fix typo in README", head: "fix", base: "main", body: "Fixes #1" }),
    ];
    for (const o of [...reads, ...writes]) {
      expect(o.isError).toBe(false);
      expect(o.details.verdict).toBeUndefined();
      expect(o.details.verify).toBe("OK");
    }
    const recs = records(log);
    expect(recs.map((r) => r.verdict)).toEqual(["ALLOWED", "ALLOWED", "ALLOWED", "ALLOWED", "ALLOWED"]);
    expect(recs.at(-1)).toMatchObject({ tool: "create_pull_request", typoFixed: true });
  });

  it("refusalNotRecordedAsInfluence", async () => {
    const c = ctx();
    const { conn } = await github(c);
    c.runs.start("fix the typo", Date.now());
    for (const o of [
      await call(conn, "list_issues", { owner: "acme", repo: "website" }),
      await call(conn, "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }),
    ]) {
      expect(o.isError).toBe(false);
    }
    const entries = c.influence.entries();
    const summary = c.influence.summary();
    for (const refused of [
      await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "leak" }),
      await call(conn, "create_or_update_file", { owner: "acme", repo: "website", path: "notes.md", content: LEAK, message: "x", branch: "leak" }),
    ]) {
      expect(refused.isError).toBe(true);
      expect(refused.details.verdict).toBe("INFLUENCE_DENIED");
      expect(refused.details.labels).toBeUndefined();
      expect(refused.details.verify).toBeUndefined();
      expect(refused.details.influence).toEqual(summary);
    }
    expect(c.influence.entries()).toEqual(entries);
  });

  it("unverifiedResponseIsUntrusted", async () => {
    // the call stamp is fresh for the server, but the client checks the response 10 s later: EXPIRED
    let tick = 0;
    const c = ctx("enforce", material, () => Date.now() + (tick++ % 2 === 0 ? 0 : 10_000));
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const out = await call(conn, "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" });
    expect(records(log)).toEqual([expect.objectContaining({ verdict: "ALLOWED", label: "private" })]);
    expect(out.isError).toBe(false);
    expect(out.details.verify).toBe("EXPIRED");
    expect(out.details.labels).toBeUndefined();
    expect(c.influence.entries()).toEqual([expect.objectContaining({ cls: "local-untrusted", src: "server:github" })]);
  });

  it("auditVerdictIsRecordedAsInfluence", async () => {
    const c = ctx();
    const { conn, log } = await github(c, "audit");
    c.runs.start("fix the typo", Date.now());
    const [, , , branch] = await leakUntilBranch(conn);
    expect(branch!.isError).toBe(false);
    expect(branch!.details.verdict).toBe("INFLUENCE_DENIED");
    expect(branch!.details.verify).toBe("OK");
    expect(branch!.details.labels).toEqual(["public"]);
    expect(c.influence.classes().has("public")).toBe(true);
    expect(records(log).at(-1)).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED", audit: true });
  });

  it("offModeNoMetaSameTools", async () => {
    const on = await github(ctx());
    const c = ctx("off");
    const { conn, log } = await github(c, "off");
    expect(conn.status()).toBe("off");
    expect(conn.tools().map((t) => t.name)).toEqual(on.conn.tools().map((t) => t.name));
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "session", server: "github", status: "off" }));
    const [, , payroll, branch] = await leakUntilBranch(conn);
    expect(payroll!.text).toContain(CANARY);
    const file = await call(conn, "create_or_update_file", { owner: "acme", repo: "website", path: "notes.md", content: LEAK, message: "x", branch: "leak" });
    for (const o of [branch!, file]) {
      expect(o.isError).toBe(false);
      expect(o.details).toMatchObject({ session: "off" });
      expect(o.details.verdict).toBeUndefined();
      expect(o.details.verify).toBeUndefined();
      expect(o.details.rid).toBeUndefined();
    }
    expect(c.influence.entries()).toEqual([]);
    const recs = records(log);
    expect(recs.find((r) => r.containsCanary)).toMatchObject({ tool: "create_or_update_file", verdict: "ALLOWED", mode: "off" });
    expect(recs.every((r) => r.rid === undefined)).toBe(true);
  });

  it("noRootIsUnsafeAndWritesRefused", async () => {
    const c = ctx("no-root");
    const { conn, log } = await github(c);
    expect(conn.status()).toBe("unsafe");
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "session", server: "github", status: "unsafe", reason: "UNSAFE" }));
    // unsafe sessions carry no stamps, so no run is needed (R6)
    const read = await call(conn, "list_issues", { owner: "acme", repo: "website" });
    expect(read.isError).toBe(false);
    expect(read.details).toMatchObject({ session: "unsafe", sessionReason: "UNSAFE" });
    expect(read.details.verify).toBeUndefined();
    expect(c.influence.entries()).toEqual([expect.objectContaining({ cls: "local-untrusted", src: "server:github" })]);
    const write = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" });
    expect(write.isError).toBe(true);
    expect(write.details.verdict).toBe("UNSAFE_SESSION");
    expect(c.influence.entries()).toHaveLength(1);
    expect(records(log).map((r) => r.verdict)).toEqual(["ALLOWED", "UNSAFE_SESSION"]);
  });

  it("wrongPinIsUnsafe", async () => {
    const pin = join(tmp, `wrong-${n++}.pub`);
    writeFileSync(pin, generateKeyPair().publicKey + "\n");
    const c = ctx();
    const { conn } = await github(c, "enforce", { pin });
    expect(conn.status()).toBe("unsafe");
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "session", server: "github", status: "unsafe", reason: "PIN_MISMATCH" }));
    c.runs.start("fix the typo", Date.now());
    const write = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" });
    expect(write.isError).toBe(true);
    expect(write.details).toMatchObject({ session: "unsafe", sessionReason: "PIN_MISMATCH" });
    expect(typeof write.details.verdict).toBe("string");
  });

  it("missingPinIsUnsafeWithoutHandshake", async () => {
    const c = ctx();
    const { conn, log } = await github(c, "enforce", { pin: join(tmp, "no-such.pub") });
    expect(conn.status()).toBe("unsafe");
    const read = await call(conn, "list_issues", { owner: "acme", repo: "website" });
    expect(read.isError).toBe(false);
    expect(read.details.sessionReason).toBe("PIN_MISSING");
    const write = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" });
    expect(write.details.verdict).toBe("UNSAFE_SESSION");
    expect(records(log).map((r) => r.verdict)).toEqual(["ALLOWED", "UNSAFE_SESSION"]);
  });

  it("handshakeMethodNotFoundIsUnsafe", async () => {
    const c = ctx();
    const { conn } = await github(c, "off");
    expect(conn.status()).toBe("unsafe");
    const read = await call(conn, "list_issues", { owner: "acme", repo: "website" });
    expect(read.details).toMatchObject({ session: "unsafe", sessionReason: "METHOD_NOT_FOUND" });
    expect(c.influence.entries()).toEqual([expect.objectContaining({ cls: "local-untrusted" })]);
  });

  it("docsServerIsUntrusted", async () => {
    const c = ctx();
    const conn = await docs(c);
    expect(conn.status()).toBe("unsafe");
    expect(conn.tools().map((t) => t.name)).toEqual(["fetch_docs"]);
    const out = await call(conn, "fetch_docs", { page: "contributing" });
    expect(out.isError).toBe(false);
    expect(out.text).toContain("Contributor guidelines");
    expect(out.details).toMatchObject({ server: "docs", session: "unsafe", sessionReason: "NOT_ATTESTED" });
    expect(out.details.influence["local-untrusted"]).toBe(1);
    expect(c.influence.entries()).toEqual([expect.objectContaining({ cls: "local-untrusted", src: "server:docs" })]);

    const off = ctx("off");
    const offConn = await docs(off);
    expect(offConn.status()).toBe("off");
    await call(offConn, "fetch_docs", { page: "contributing" });
    expect(off.influence.entries()).toEqual([]);
  });

  it("scenarioB_crossSourceDenied", async () => {
    const c = ctx();
    const d = await docs(c);
    const { conn } = await github(c);
    c.runs.start("fix the typo", Date.now());
    expect((await call(d, "fetch_docs", { page: "contributing" })).isError).toBe(false);
    const payroll = await call(conn, "get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" });
    expect(payroll.details.labels).toEqual(["private"]);
    const branch = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "credits" });
    expect(branch.isError).toBe(true);
    expect(branch.details.verdict).toBe("INFLUENCE_DENIED");
  });

  it("unsafeToolCallIdReplaced", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const bad = ["a\nb", "a|b", "x".repeat(129), "", "a/b"];
    const ids: string[] = [];
    for (const id of bad) {
      const out = await conn.call("list_issues", { owner: "acme", repo: "website" }, id);
      expect(out.isError).toBe(false);
      expect(out.details.verify).toBe("OK");
      expect(out.details.callId).toMatch(CALL_ID);
      expect(out.details.callId).not.toBe(id);
      ids.push(out.details.callId);
    }
    const ok = "x".repeat(128);
    expect((await conn.call("list_issues", { owner: "acme", repo: "website" }, ok)).details.callId).toBe(ok);
    expect(new Set(ids).size).toBe(bad.length);
    expect(records(log).map((r) => r.callId)).toEqual([...ids, ok]);
  });

  it("parallelCallsEachStamped", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const [a, b] = await Promise.all([
      conn.call("list_issues", { owner: "acme", repo: "website" }, "p1"),
      conn.call("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }, "p2"),
    ]);
    expect([a!.details.verify, b!.details.verify]).toEqual(["OK", "OK"]);
    expect(c.influence.classes()).toEqual(new Set(["third-party", "private"]));
    expect(records(log).map((r) => r.callId).sort()).toEqual(["p1", "p2"]);
  });

  it("serverExitIsToolError", async () => {
    const c = ctx();
    const d = await docs(c);
    const { conn } = await github(c);
    c.runs.start("fix the typo", Date.now());
    process.kill(conn.pid!, "SIGKILL");
    for (const tool of ["list_issues", "create_branch"]) {
      const out = await call(conn, tool, { owner: "acme", repo: "website", branch: "b" });
      expect(out.isError).toBe(true);
      expect(out.text).toMatch(/^MCP server "github" error: /);
      expect(out.details.server).toBe("github");
    }
    expect(c.influence.entries()).toEqual([]);
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "error", server: "github", code: "TRANSPORT" }));
    expect((await call(d, "fetch_docs", { page: "intro" })).isError).toBe(false);
  });

  it("noRunRefusesLocally", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    const out = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" });
    expect(out.isError).toBe(true);
    expect(out.text).toMatch(/no active run/);
    expect(out.details.session).toBe("attested");
    expect(records(log)).toEqual([]);
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "error", server: "github", tool: "create_branch", code: "NO_ACTIVE_RUN" }));
  });

  it("missingProofRefusedLocally", async () => {
    const proofs = Object.fromEntries(Object.entries(material.proofs).filter(([route]) => !route.endsWith(".create_branch")));
    const c = ctx("enforce", { ...material, proofs });
    const { conn, log } = await github(c);
    c.runs.start("fix the typo", Date.now());
    const out = await call(conn, "create_branch", { owner: "acme", repo: "website", branch: "x" });
    expect(out.isError).toBe(true);
    expect(out.text).toMatch(/no policy proof/);
    expect(records(log)).toEqual([]);
    expect(events(c)).toContainEqual(expect.objectContaining({ type: "error", code: "NO_PROOF" }));
  });

  it("eventsLogHasNoSecrets", async () => {
    const c = ctx();
    const { conn, log } = await github(c);
    await call(conn, "list_issues", { owner: "acme", repo: "website" }); // no run: an error event
    c.runs.start("fix the typo", Date.now());
    await leakUntilBranch(conn);
    const text = readFileSync(c.eventsPath, "utf8");
    const types = new Set(events(c).map((e) => e.type));
    for (const t of ["session", "call", "response", "error"]) expect(types.has(t)).toBe(true);
    expect(events(c).filter((e) => e.type === "response").map((e) => e.verdict)).toContain("INFLUENCE_DENIED");
    for (const side of ["client", "server"]) {
      const dir = join(demo, side);
      for (const f of readdirSync(dir).filter((f) => f.endsWith(".key"))) {
        expect(text).not.toContain(readFileSync(join(dir, f), "utf8").trim());
      }
      expect(text).not.toContain(JSON.parse(readFileSync(join(dir, "root.json"), "utf8")).sig);
    }
    expect(text.toLowerCase()).not.toContain(CANARY);
    expect(text).not.toContain("paztport/");
    expect(text).not.toContain("Payroll notes");
    expect(text).not.toContain("payroll-notes");
    for (const r of records(log)) if (r.sess) expect(text).not.toContain(r.sess);
    const banned = new Set(["sig", "sess", "h", "cid", "args", "arguments", "text", "content"]);
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (typeof v === "object" && v !== null) {
        for (const [k, x] of Object.entries(v)) {
          expect(banned.has(k), `key ${k}`).toBe(false);
          walk(x);
        }
      }
    };
    events(c).forEach((e) => {
      expect(typeof e.ts).toBe("number");
      walk(e);
    });
  });
});

describe("EventLog", () => {
  it("appendsJsonlWithTs", () => {
    const path = join(tmp, `ev-${n++}.jsonl`);
    const log = new EventLog(path);
    log.emit({ type: "a" });
    log.emit({ type: "b", x: 1 });
    const lines = records(path);
    expect(lines.map((l) => l.type)).toEqual(["a", "b"]);
    expect(lines.every((l) => typeof l.ts === "number")).toBe(true);
  });

  it("noPathIsNoop", () => {
    expect(() => new EventLog(undefined).emit({ type: "a" })).not.toThrow();
  });
});
