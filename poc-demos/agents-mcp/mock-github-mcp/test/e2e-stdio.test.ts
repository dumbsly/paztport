// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { META_ATTESTATION, META_CALL_ID, META_CHAIN, SESSION_METHOD, type InfluenceEntry, type SessionReply } from "@paztport/core";
import type { CallToolResult } from "../src/mcp.ts";
import { META_VERDICT } from "../src/paztport.ts";
import { makeClient } from "./helpers/client.ts";

const MAIN = join(import.meta.dirname, "../src/main.ts");
const SETUP = join(import.meta.dirname, "../../scripts/setup-demo.ts");
const CANARY = "c0ffee";
const LEAK = `Notes copied from payroll: Reference: ${CANARY}\n`;

let tmp: string;
let demo: string;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-e2e-"));
  demo = join(tmp, "demo");
  const r = spawnSync(process.execPath, [SETUP, "--out", demo], { encoding: "utf8" });
  expect(r.status, r.stderr).toBe(0);
});
const children = new Set<ChildProcessWithoutNullStreams>();
const killAll = () => {
  for (const c of children) c.kill("SIGKILL");
  children.clear();
};
afterEach(killAll);
afterAll(() => {
  killAll();
  rmSync(tmp, { recursive: true, force: true });
});

type Session = {
  child: ChildProcessWithoutNullStreams;
  stdout: string[];
  unparseable: string[];
  rpc(method: string, params?: unknown): Promise<any>;
  close(): Promise<void>;
};

function start(args: string[]): Session {
  const child = spawn(process.execPath, [MAIN, ...args], { stdio: ["pipe", "pipe", "pipe"] });
  children.add(child);
  child.stderr.resume();
  const stdout: string[] = [];
  const unparseable: string[] = [];
  const waiting = new Map<number, { resolve(m: any): void; reject(e: Error): void }>();
  const failAll = (why: string) => {
    for (const w of waiting.values()) w.reject(new Error(why));
    waiting.clear();
  };
  child.on("error", (e) => failAll(`child error: ${e.message}`));
  child.on("exit", (code, sig) => failAll(`child exited (code ${code}, signal ${sig}) with requests pending`));
  child.stdin.on("error", () => {});
  createInterface({ input: child.stdout }).on("line", (line) => {
    stdout.push(line);
    let m: any;
    try {
      m = JSON.parse(line);
    } catch {
      unparseable.push(line);
      return;
    }
    const w = waiting.get(m?.id);
    if (w) {
      waiting.delete(m.id);
      w.resolve(m);
    }
  });
  let id = 0;
  return {
    child,
    stdout,
    unparseable,
    rpc(method, params) {
      const n = ++id;
      return new Promise((resolve, reject) => {
        waiting.set(n, { resolve, reject });
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: n, method, params }) + "\n");
      });
    },
    close() {
      const done = new Promise<void>((r) => child.on("close", () => r()));
      child.stdin.end();
      return done;
    },
  };
}

/** The scenario A leak sequence, signed like the plan 1c harness once a session is accepted. */
async function leakSequence(s: Session, attested: boolean) {
  const client = makeClient({ fromDir: join(demo, "client") });
  // the harness pins the server key from the client dir, as setup-demo wrote it
  const pinned = readFileSync(join(demo, "client/server-policy.pub"), "utf8").trim();
  let reply: SessionReply | undefined;
  if (attested) {
    const r = await s.rpc(SESSION_METHOD, client.request());
    reply = r.result as SessionReply;
    expect(client.acceptReply(reply, pinned)).toBe(true);
    expect(reply.status).toBe("attested");
  }
  const influence: InfluenceEntry[] = [];
  const call = async (name: string, args: Record<string, unknown>): Promise<CallToolResult> => {
    const params = reply ? client.callParams(name, args, [...influence]) : { name, arguments: args };
    const r = await s.rpc("tools/call", params);
    expect(r.error).toBeUndefined();
    const result = r.result as CallToolResult;
    if (reply && result._meta?.[META_ATTESTATION] !== undefined) {
      const meta = (params as { _meta: Record<string, unknown> })._meta;
      const rid = (meta[META_CHAIN] as { rid: string }[])[0]!.rid;
      const v = client.verify(result, { rid, toolCallId: meta[META_CALL_ID] as string }, reply.serverKeyring, reply.serverRoot!);
      expect(v.reason).toBe("OK");
      for (const l of v.labels) influence.push({ cls: l.cls, src: `github.${name}`, h: l.cid, cid: l.cid });
    }
    return result;
  };
  await call("list_issues", { owner: "acme", repo: "website" });
  await call("search_repositories", { query: "user:acme" });
  const payroll = await call("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" });
  expect(payroll.content[0]!.text).toContain(CANARY);
  const branch = await call("create_branch", { owner: "acme", repo: "website", branch: "leak" });
  const file = await call("create_or_update_file", { owner: "acme", repo: "website", path: "notes.md", content: LEAK, message: "Add notes", branch: "leak" });
  const pr = await call("create_pull_request", { owner: "acme", repo: "website", title: "Add notes", head: "leak", base: "main" });
  return { branch, file, pr };
}

const records = (path: string) => readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

describe("stdio end to end", () => {
  it("e2eLeakDeniedAndLogged", async () => {
    const log = join(tmp, "enforce.jsonl");
    const s = start(["--config", join(demo, "server"), "--outcome-log", log, "--canary", CANARY]);
    const init = await s.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
    expect(init.result.serverInfo.name).toBe("mock-github-mcp");
    const { branch, file, pr } = await leakSequence(s, true);
    for (const r of [branch, file, pr]) {
      expect(r.isError).toBe(true);
      expect(r._meta?.[META_VERDICT]).toEqual({ reason: "INFLUENCE_DENIED" });
    }
    await s.close();
    const recs = records(log);
    expect(recs.map((r) => [r.tool, r.verdict, r.audit])).toEqual([
      ["list_issues", "ALLOWED", false],
      ["search_repositories", "ALLOWED", false],
      ["get_file_contents", "ALLOWED", false],
      ["create_branch", "INFLUENCE_DENIED", false],
      ["create_or_update_file", "INFLUENCE_DENIED", false],
      ["create_pull_request", "INFLUENCE_DENIED", false],
    ]);
    expect(recs[2]).toMatchObject({ kind: "read", label: "private", privateRead: true, containsCanary: false });
    expect(recs[4]).toMatchObject({ kind: "write", mode: "enforce", containsCanary: true, publicDestination: true });
    for (const r of recs) expect(typeof r.rid).toBe("string");
  });

  it("e2eOffModeLeaks", async () => {
    const log = join(tmp, "off.jsonl");
    const s = start(["--mode", "off", "--outcome-log", log, "--canary", CANARY, "--config", join(tmp, "does-not-exist")]);
    const { branch, file, pr } = await leakSequence(s, false);
    for (const r of [branch, file, pr]) expect(r.isError).toBeFalsy();
    const comment = await s.rpc("tools/call", { name: "add_issue_comment", arguments: { owner: "acme", repo: "website", issue_number: 1, body: "See ACME/Roadmap." } });
    expect(comment.result.isError).toBeFalsy();
    await s.close();
    const recs = records(log);
    const leaked = recs.find((r) => r.containsCanary);
    expect(leaked).toMatchObject({ tool: "create_or_update_file", verdict: "ALLOWED", mode: "off" });
    expect(recs.at(-1)).toMatchObject({ tool: "add_issue_comment", containsPrivateMarker: true, containsCanary: false });
  });

  it("offModeNeedsNoConfig", async () => {
    const s = start(["--mode", "off"]);
    const r = await s.rpc("tools/list");
    expect(r.result.tools).toHaveLength(9);
    await s.close();
  });

  it("missingConfigExits2", () => {
    for (const mode of ["enforce", "audit"]) {
      const r = spawnSync(process.execPath, [MAIN, "--mode", mode, "--config", join(tmp, "nope")], { encoding: "utf8" });
      expect(r.status).toBe(2);
      expect(r.stdout).toBe("");
      expect(r.stderr).toMatch(/Usage/);
    }
  });

  it("stdoutCarriesOnlyJsonRpc", async () => {
    const s = start(["--config", join(demo, "server"), "--canary", CANARY]);
    await s.rpc("initialize", { protocolVersion: "2025-06-18" });
    await leakSequence(s, true);
    s.child.stdin.write("not json\n");
    await s.rpc("ping");
    await s.close();
    expect(s.unparseable).toEqual([]);
    expect(s.stdout.length).toBeGreaterThan(7);
    for (const line of s.stdout) {
      const m = JSON.parse(line);
      expect(m.jsonrpc).toBe("2.0");
      expect("result" in m || "error" in m).toBe(true);
    }
  });
});
