// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AgentToolResult,
  ExtensionAPI,
  ExtensionContext,
  ExtensionToolContext,
  SessionEntry,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { ServerSpec } from "../src/config.ts";
import type { CallOutcome } from "../src/connection.ts";
import paztport, { mcpToolName } from "../src/index.ts";
import { GITHUB_TOOLS } from "../../mock-github-mcp/src/github.ts";
import { CANARY, DOCS, githubArgs, records, setupDemo, STUB } from "./helpers/demo.ts";

type Handler = (event: Record<string, unknown>, ctx: ExtensionContext) => unknown;
type Result = AgentToolResult<CallOutcome["details"]>;

/**
 * Records what the extension registers. It keeps the first registration of a tool name, as pi does
 * across extensions; within one extension real pi 1.4.0 replaces it, and the extension must work
 * either way. Names in `throwOn` make registerTool throw.
 */
class FakePi {
  readonly throwOn = new Set<string>();
  readonly flags = new Map<string, unknown>();
  readonly tools = new Map<string, ToolDefinition>();
  readonly registrations: string[] = [];
  readonly handlers = new Map<string, Handler[]>();
  readonly api: ExtensionAPI;
  readonly ctx: ExtensionContext;
  /** The session branch ctx.sessionManager.getBranch() returns: what pi restored for this session. */
  branch: SessionEntry[] = [];

  constructor(flagValues: Record<string, string | undefined>, cwd: string) {
    const sessionManager: Pick<ExtensionContext["sessionManager"], "getBranch"> = { getBranch: () => [...this.branch] };
    this.ctx = { cwd, sessionManager } as unknown as ExtensionContext;
    this.api = {
      registerFlag: (name: string, options: unknown) => void this.flags.set(name, options),
      getFlag: (name: string) => flagValues[name],
      registerTool: (tool: ToolDefinition) => {
        if (this.throwOn.has(tool.name)) throw new Error(`cannot register ${tool.name}`);
        this.registrations.push(tool.name);
        if (!this.tools.has(tool.name)) this.tools.set(tool.name, tool);
      },
      on: (event: string, handler: Handler) => {
        this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
        return () => {};
      },
    } as unknown as ExtensionAPI;
  }

  async emit(type: string, event: Record<string, unknown> = {}): Promise<void> {
    for (const h of this.handlers.get(type) ?? []) await h({ type, ...event }, this.ctx);
  }

  prompt(prompt: string): Promise<void> {
    return this.emit("before_agent_start", { messageType: "user", prompt, systemPrompt: "" });
  }

  execute(name: string, params: Record<string, unknown>, toolCallId: string): Promise<Result> {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`no tool ${name}`);
    return tool.execute(toolCallId, params, undefined, undefined, this.ctx as ExtensionToolContext) as Promise<Result>;
  }
}

let tmp: string;
let demo: string;
let workspace: string;
let n = 0;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-ext-"));
  demo = setupDemo(tmp);
  workspace = join(tmp, "workspace");
  mkdirSync(workspace);
});
beforeEach(() => {
  vi.stubEnv("PAZTPORT_CONFIG", "");
});
const started: FakePi[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(started.splice(0).map((pi) => pi.emit("session_shutdown", { reason: "quit" })));
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Setup = { pi: FakePi; eventsPath: string };

/** Writes a config, loads the extension into a FakePi with --paztport-config pointing at it. */
function setup(
  servers: ServerSpec[],
  opts: { mode?: string; eventsLog?: boolean; cwd?: string; clientDir?: string; raw?: string; configDir?: string } = {},
): Setup {
  const eventsPath = join(tmp, `events-${n++}.jsonl`);
  const path = join(opts.configDir ?? tmp, `config-${n++}.json`);
  const config = {
    mode: opts.mode ?? "enforce",
    clientDir: opts.clientDir ?? join(demo, "client"),
    servers,
    ...(opts.eventsLog !== false ? { eventsLog: eventsPath } : {}),
  };
  writeFileSync(path, opts.raw ?? JSON.stringify(config));
  const pi = new FakePi({ "paztport-config": path }, opts.cwd ?? workspace);
  paztport(pi.api);
  started.push(pi);
  return { pi, eventsPath };
}

function github(outcomeLog: string = join(tmp, `outcome-${n++}.jsonl`)): ServerSpec {
  return { id: "github", command: process.execPath, args: githubArgs(demo, "enforce", outcomeLog), attested: true };
}

/** The docs server, with a payload file whose path marks its process. */
function docs(): ServerSpec {
  const payload = join(tmp, `docs-payload-${n++}.md`);
  writeFileSync(payload, "Contributor guidelines: be kind.\n");
  return { id: "docs", command: process.execPath, args: [DOCS, "--payload", payload], attested: false };
}

/** How many running processes have the marker on their command line. */
function running(marker: string): number {
  const r = spawnSync("ps", ["-ax", "-o", "command="], { encoding: "utf8" });
  return r.stdout.split("\n").filter((l) => l.includes(marker)).length;
}

async function until(cond: () => boolean, ms = 5_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

let entrySeq = 0;
/** A session entry for a tool result, shaped as pi 1.4.0 stores it. */
function toolResultEntry(toolName: string, content: unknown, details?: unknown, isError = false): SessionEntry {
  const id = `e${entrySeq++}`;
  return {
    type: "message",
    id,
    parentId: null,
    timestamp: new Date(0).toISOString(),
    message: { role: "toolResult", toolCallId: `call_${id}`, toolName, content, details, isError, timestamp: 0 },
  } as unknown as SessionEntry;
}

const LIST = { owner: "acme", repo: "website" };
const PAYROLL = { owner: "acme", repo: "payroll-notes", path: "README.md" };
const ZERO = { "third-party": 0, private: 0, public: 0, "local-untrusted": 0 };
let seq = 0;
const id = () => `toolu_${seq++}`;

describe("paztport pi extension", { timeout: 30_000 }, () => {
  it("inertWithoutConfig", async () => {
    const pi = new FakePi({}, workspace);
    paztport(pi.api);
    started.push(pi);
    expect(pi.flags.get("paztport-config")).toMatchObject({ type: "string" });
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    await pi.emit("tool_result", { toolName: "mcp__other__x", toolCallId: "b", input: {}, content: [{ type: "text", text: "x" }], isError: false });
    expect(pi.registrations).toEqual([]);
  });

  it("refusesWhenKeysInsideWorkspace", async () => {
    const { pi, eventsPath } = setup([github()], { cwd: demo });
    await expect(pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/inside the workspace/);
    expect(pi.registrations).toEqual([]);
    expect(records(eventsPath)).toEqual([expect.objectContaining({ type: "refused_start", code: "WORKSPACE_GUARD" })]);

    // client material that does not load: refused after the config named the events log
    const empty = join(tmp, `empty-client-${n++}`);
    mkdirSync(empty);
    const bad = setup([github()], { clientDir: empty });
    await expect(bad.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/Paztport refused to start/);
    expect(bad.pi.registrations).toEqual([]);
    expect(records(bad.eventsPath)).toEqual([expect.objectContaining({ type: "refused_start", code: "CLIENT_MATERIAL" })]);

    // a config that does not load names no events log: the error alone is surfaced (R7)
    const broken = setup([], { raw: "{ not json" });
    await expect(broken.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/cannot read config/);
    expect(broken.pi.registrations).toEqual([]);
    expect(existsSync(broken.eventsPath)).toBe(false);
  });

  it("refusesWhenConfigOrPinInsideWorkspace", async () => {
    // R14: a config the agent can edit is refused, and its eventsLog is not trusted either
    const cfg = setup([github()], { configDir: workspace });
    await expect(cfg.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/config .* is inside the workspace/);
    expect(cfg.pi.registrations).toEqual([]);
    expect(existsSync(cfg.eventsPath)).toBe(false);

    const pin = join(workspace, `pin-${n++}.pub`);
    copyFileSync(join(demo, "client/server-policy.pub"), pin);
    const pinned = setup([{ ...github(), pin }, docs()]);
    await expect(pinned.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/pin .* is inside the workspace/);
    expect(pinned.pi.registrations).toEqual([]);
    expect(records(pinned.eventsPath)).toEqual([expect.objectContaining({ type: "refused_start", code: "WORKSPACE_GUARD" })]);

    // a pin that does not exist yet is judged by where it would be
    const missing = setup([{ ...github(), pin: join(workspace, `later-${n++}/pin.pub`) }]);
    await expect(missing.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/inside the workspace/);
    expect(missing.pi.registrations).toEqual([]);
  });

  it("registersNamespacedTools", async () => {
    const { pi } = setup([github(), docs()]);
    await pi.emit("session_start", { reason: "startup" });
    expect(GITHUB_TOOLS).toHaveLength(9);
    expect(pi.registrations.filter((name) => name.startsWith("mcp__github__"))).toHaveLength(9);
    expect([...pi.tools.keys()].sort()).toEqual([...GITHUB_TOOLS.map((t) => `mcp__github__${t.name}`), "mcp__docs__fetch_docs"].sort());
    for (const t of GITHUB_TOOLS) {
      const def = pi.tools.get(`mcp__github__${t.name}`)!;
      expect(def.label).toBe(t.name);
      expect(def.description).toBe(t.description);
      expect(def.parameters).toEqual(t.inputSchema);
      expect((def.parameters as { required?: string[] }).required).toEqual((t.inputSchema as { required?: string[] }).required);
      expect(def.namespace).toEqual({ name: "mcp__github", aliases: ["github"] });
    }
    expect(pi.tools.get("mcp__github__create_pull_request")!.parameters).toMatchObject({ required: ["owner", "repo", "title", "head", "base"] });
    const fetch = pi.tools.get("mcp__docs__fetch_docs")!;
    expect(fetch.annotations).toEqual({ readOnlyHint: true });
    expect(fetch.namespace).toEqual({ name: "mcp__docs", aliases: ["docs"] });
  });

  it("sanitisesNamesAndDefaultsSchemaType", async () => {
    expect(mcpToolName("my-srv", "a.b/c")).toBe("mcp__my_srv__a_b_c");
    const long1 = mcpToolName("server", "x".repeat(80) + "1");
    const long2 = mcpToolName("server", "x".repeat(80) + "2");
    expect(long1).toMatch(/^mcp__server__x+_[0-9a-f]{8}$/);
    expect(long1.length).toBe(64);
    expect(long1).not.toBe(long2);

    const { pi } = setup([{ id: "stub-1", command: process.execPath, args: [STUB], attested: false }]);
    await pi.emit("session_start", { reason: "startup" });
    const untyped = pi.tools.get("mcp__stub_1__untyped_tool")!;
    expect(untyped.parameters).toEqual({ type: "object", properties: { x: { type: "string" } } });
    expect(untyped.namespace).toEqual({ name: "mcp__stub_1", aliases: ["stub-1"] });
    expect(pi.tools.get("mcp__stub_1__echo")!.parameters).toEqual({ type: "object" });
    // a non-object schema is forced to an object one, so provider requests stay valid
    expect(pi.tools.get("mcp__stub_1__stringly")!.parameters).toEqual({ type: "object" });
    // execute calls the remote name, not the sanitised one
    const out = await pi.execute("mcp__stub_1__echo", {}, id());
    expect(out.isError).toBe(false);
    expect(JSON.parse((out.content[0] as { text: string }).text).methods).toContain("tools/call");
  });

  it("promptStartsRun", async () => {
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    const before = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(before.isError).toBe(true);
    expect(before.content).toEqual([{ type: "text", text: expect.stringMatching(/no active run/) }]);

    await pi.prompt("fix the typo");
    const a = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(a.isError).toBe(false);
    const rid = a.details.rid!;
    expect(rid).toMatch(/^[A-Za-z0-9_-]+$/);

    await pi.emit("before_agent_start", { messageType: "custom", message: { customType: "note", content: "x" }, systemPrompt: "" });
    const b = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(b.details.rid).toBe(rid);

    await pi.prompt("now something else");
    const c = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(c.details.rid).toBeDefined();
    expect(c.details.rid).not.toBe(rid);
    expect(records(outcome).map((r) => r.rid)).toEqual([rid, rid, c.details.rid]);
  });

  it("executeReturnsTextOnlyContent", async () => {
    const { pi } = setup([github()]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    await pi.execute("mcp__github__list_issues", LIST, id());
    const out = await pi.execute("mcp__github__get_file_contents", PAYROLL, id());
    expect(Object.keys(out).sort()).toEqual(["content", "details", "isError"]);
    expect(out.isError).toBe(false);
    expect(out.content).toEqual([{ type: "text", text: expect.stringContaining(CANARY) }]);
    expect(JSON.stringify(out.content)).not.toMatch(/paztport\/|_meta|"sig"/);
    expect(out.details).toMatchObject({ server: "github", verify: "OK", labels: ["private"], session: "attested" });
    expect(out.details.influence).toEqual({ ...ZERO, "third-party": 1, private: 1 });

    const refused = await pi.execute("mcp__github__create_branch", { ...LIST, branch: "leak" }, id());
    expect(refused.isError).toBe(true);
    expect(refused.content).toEqual([{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }]);
    expect(refused.details.verdict).toBe("INFLUENCE_DENIED");

    const banned = new Set(["sig", "sess", "h", "cid", "_meta", "chain", "proof"]);
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (typeof v === "object" && v !== null) {
        for (const [k, x] of Object.entries(v)) {
          expect(banned.has(k), `key ${k}`).toBe(false);
          walk(x);
        }
      }
    };
    walk([out, refused]);
  });

  it("builtinMcpResultsAreUntrusted", async () => {
    const { pi } = setup([github()]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const result = (toolName: string, text: string) =>
      pi.emit("tool_result", { toolName, toolCallId: id(), input: {}, content: [{ type: "text", text }], isError: false, details: undefined });
    await result("mcp__other__fetch", "from a built-in MCP server");
    await result("mcp__other__fetch", "bad \ud800 text"); // JCS rejects it; still recorded
    await result("read_mcp_resource", "a built-in MCP resource");
    // a result with no content at all is still recorded, not a throw
    await pi.emit("tool_result", { toolName: "mcp__other__empty", toolCallId: id(), input: {}, content: undefined, isError: false });
    await result("bash", "local output");
    await result("read", "a local file");
    // this extension's own call, seen again by tool_result under the same toolCallId: not relabelled
    const ownId = id();
    const first = await pi.execute("mcp__github__list_issues", LIST, ownId);
    await pi.emit("tool_result", { toolName: "mcp__github__list_issues", toolCallId: ownId, input: LIST, content: first.content, isError: false, details: first.details });
    // pi's built-in MCP using a name this extension registered (the same server in mcp.json): a call
    // this extension never executed is still recorded
    await result("mcp__github__list_issues", "from the built-in MCP github server");
    const out = await pi.execute("mcp__github__list_issues", LIST, id());
    // two list_issues results (each labelled), five built-in MCP results
    expect(out.details.influence).toEqual({ ...ZERO, "third-party": 2, "local-untrusted": 5 });
  });

  it("parallelCallsKeepInfluence", async () => {
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const [a, b] = await Promise.all([
      pi.execute("mcp__github__list_issues", LIST, "p1"),
      pi.execute("mcp__github__get_file_contents", PAYROLL, "p2"),
    ]);
    expect([a!.details.verify, b!.details.verify]).toEqual(["OK", "OK"]);
    expect([a!.details.callId, b!.details.callId]).toEqual(["p1", "p2"]);
    // whichever call recorded last saw both labels
    expect([a!.details.influence, b!.details.influence]).toContainEqual({ ...ZERO, "third-party": 1, private: 1 });
    expect(records(outcome).map((r) => [r.callId, r.verdict]).sort()).toEqual([["p1", "ALLOWED"], ["p2", "ALLOWED"]]);
  });

  it("failedServerDoesNotBlockOthers", async () => {
    const broken: ServerSpec = { id: "broken", command: process.execPath, args: [join(tmp, "no-such-server.ts")], attested: false };
    const { pi, eventsPath } = setup([broken, docs()]);
    await expect(pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/broken/);
    expect(pi.registrations).toEqual(["mcp__docs__fetch_docs"]);
    expect(records(eventsPath)).toContainEqual(expect.objectContaining({ type: "error", server: "broken", code: "CONNECT_FAILED" }));
    await pi.prompt("fix the typo");
    expect((await pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id())).isError).toBe(false);
  });

  it("registerToolFailureDoesNotStrandOthers", async () => {
    const stubSpec: ServerSpec = { id: "stub", command: process.execPath, args: [STUB], attested: false };
    const { pi } = setup([stubSpec, docs()]);
    pi.throwOn.add("mcp__stub__echo");
    await expect(pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/mcp__stub__echo/);
    expect(pi.registrations).toContain("mcp__stub__surrogate");
    expect(pi.registrations).toContain("mcp__docs__fetch_docs");
    expect(pi.tools.has("mcp__stub__echo")).toBe(false);
    expect((await pi.execute("mcp__docs__fetch_docs", { page: "intro" }, id())).isError).toBe(false);
  });

  it("sessionStartReconnects", async () => {
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    await pi.execute("mcp__github__list_issues", LIST, id());
    expect((await pi.execute("mcp__github__get_file_contents", PAYROLL, id())).details.influence.private).toBe(1);

    await pi.emit("session_start", { reason: "new" });
    // the old server is gone, one new one runs, and the first registrations reach it
    await until(() => running(outcome) === 1);
    expect(pi.registrations.filter((name) => name === "mcp__github__create_branch")).toHaveLength(2);
    const noRun = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(noRun.content).toEqual([{ type: "text", text: expect.stringMatching(/no active run/) }]);
    await pi.prompt("fix the typo");
    const fresh = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(fresh.details.influence).toEqual({ ...ZERO, "third-party": 1 });
    // a fresh server session holds no private taint, so the write is allowed
    const branch = await pi.execute("mcp__github__create_branch", { ...LIST, branch: "fix" }, id());
    expect(branch.isError).toBe(false);
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "ALLOWED" });
  });

  it("restoredBranchKeepsInfluence", async () => {
    // A poisoned session: the issues (third-party) and the private notes reached the model.
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    for (const [tool, args] of [["list_issues", LIST], ["get_file_contents", PAYROLL]] as const) {
      const out = await pi.execute(`mcp__github__${tool}`, args, id());
      pi.branch.push(toolResultEntry(`mcp__github__${tool}`, out.content, out.details));
    }
    const poisoned = { ...ZERO, "third-party": 1, private: 1 };

    // reload keeps the messages; resume, fork and a startup with -c or --session restore them. Each
    // reconnects (a fresh server session), but the context is still poisoned, so the write is refused.
    for (const reason of ["reload", "resume", "fork", "startup"]) {
      await pi.emit("session_start", { reason });
      await pi.prompt("fix the typo");
      const write = await pi.execute("mcp__github__create_branch", { ...LIST, branch: `leak-${reason}` }, id());
      expect(write.details.verdict, reason).toBe("INFLUENCE_DENIED");
      expect(write.details.influence, reason).toEqual(poisoned);
      expect(records(outcome).at(-1), reason).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED" });
    }

    // /new: an empty branch is a clean context
    pi.branch = [];
    await pi.emit("session_start", { reason: "new" });
    await pi.prompt("fix the typo");
    const write = await pi.execute("mcp__github__create_branch", { ...LIST, branch: "fix" }, id());
    expect(write.isError).toBe(false);
    expect(write.details.influence).toEqual({ ...ZERO, public: 1 }); // only the write's own result
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "ALLOWED" });
  });

  it("restoredBranchRecordedLikeLivePath", async () => {
    const own = (extra: Record<string, unknown>) => ({ server: "github", callId: id(), influence: ZERO, ...extra });
    const branch = [
      // this extension's results: verified labels are re-recorded as their classes
      toolResultEntry("mcp__github__get_file_contents", [{ type: "text", text: "notes" }], own({ session: "attested", verify: "OK", labels: ["private"] })),
      // unverified, or from an unsafe session: local-untrusted
      toolResultEntry("mcp__github__list_issues", [{ type: "text", text: "issues" }], own({ session: "unsafe", sessionReason: "PIN_MISMATCH" })),
      // a refusal carries no server content and is never recorded
      toolResultEntry("mcp__github__create_branch", [{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }], own({ session: "attested", verdict: "INFLUENCE_DENIED" }), true),
      // pi's built-in MCP (details { server, tool }), even under a name this extension registers
      toolResultEntry("mcp__github__list_issues", [{ type: "text", text: "built-in github" }], { server: "github", tool: "list_issues" }),
      toolResultEntry("mcp__other__fetch", [{ type: "text", text: "built-in other" }], { server: "other", tool: "fetch" }),
      toolResultEntry("read_mcp_resource", [{ type: "text", text: "a resource" }], { server: "other", tool: "read_mcp_resource" }),
      toolResultEntry("mcp__other__empty", undefined),
      // not MCP content
      toolResultEntry("bash", [{ type: "text", text: "local output" }]),
      { type: "message", id: "u", parentId: null, timestamp: new Date(0).toISOString(), message: { role: "user", content: "hi", timestamp: 0 } } as unknown as SessionEntry,
      { type: "model_change", id: "m", parentId: null, timestamp: new Date(0).toISOString(), provider: "p", modelId: "m" } as SessionEntry,
    ];

    const enforce = setup([github(), docs()]);
    enforce.pi.branch = branch;
    await enforce.pi.emit("session_start", { reason: "reload" });
    // one unsafe result of ours and four built-in MCP results, plus the live docs result (the docs
    // server is unattested)
    const a = await enforce.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id());
    expect(a.details.influence).toEqual({ ...ZERO, private: 1, "local-untrusted": 6 });

    // off mode records none of this extension's results (restored or live); the four built-in MCP
    // results still count
    const off = setup([github(), docs()], { mode: "off" });
    off.pi.branch = branch;
    await off.pi.emit("session_start", { reason: "resume" });
    const b = await off.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id());
    expect(b.details.influence).toEqual({ ...ZERO, "local-untrusted": 4 });
  });

  it("shutdownClosesServers", async () => {
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const d = docs();
    const payload = d.args![2]!;
    const { pi } = setup([github(outcome), d]);
    await pi.emit("session_start", { reason: "startup" });
    expect(running(outcome)).toBe(1);
    expect(running(payload)).toBe(1);
    await pi.emit("session_shutdown", { reason: "quit" });
    await until(() => running(outcome) === 0 && running(payload) === 0);
    await pi.prompt("fix the typo");
    const out = await pi.execute("mcp__github__list_issues", LIST, id());
    expect(out.isError).toBe(true);
    expect(out.content).toEqual([{ type: "text", text: 'MCP server "github" is not connected' }]);
    await pi.emit("session_shutdown", { reason: "quit" }); // idempotent
  });
});
