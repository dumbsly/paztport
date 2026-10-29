// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
import { SessionManager } from "@earendil-works/pi-coding-agent";
import type { ToolResultMessage } from "@earendil-works/pi-ai";
import type { ServerSpec } from "../src/config.ts";
import type { CallOutcome } from "../src/connection.ts";
import paztport, { mcpToolName } from "../src/index.ts";
import { GITHUB_TOOLS } from "../../mock-github-mcp/src/github.ts";
import { POLICY_EXPIRED_TEXT, SCOPE_TEXT, UNCHECKABLE_TEXT } from "../src/refusals.ts";
import { CANARY, DOCS, githubArgs, records, resignDemo, setupDemo, STUB, UNSAFE_TEXT } from "./helpers/demo.ts";

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
  /**
   * The session branch ctx.sessionManager.getBranch() returns: what pi restored for this session.
   * A flat path with no tree, header or session file behind it: getEntry finds only these.
   */
  branch: SessionEntry[] = [];
  /** A real pi session (a tree) to read instead of `branch`, when set. */
  session: SessionManager | undefined;

  constructor(flagValues: Record<string, string | undefined>, cwd: string) {
    const sessionManager: Pick<ExtensionContext["sessionManager"], "getBranch" | "getEntry" | "getHeader" | "getSessionDir"> = {
      getBranch: (fromId?: string) =>
        this.session !== undefined ? this.session.getBranch(fromId) : fromId === undefined ? [...this.branch] : [],
      getEntry: (id: string) => (this.session !== undefined ? this.session.getEntry(id) : this.branch.find((e) => e.id === id)),
      getHeader: () => (this.session !== undefined ? this.session.getHeader() : null),
      getSessionDir: () => (this.session !== undefined ? this.session.getSessionDir() : ""),
    };
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

  /** The first handler's return value, for hooks whose result pi uses (tool_call, tool_result). */
  async call(type: string, event: Record<string, unknown>): Promise<unknown> {
    return (this.handlers.get(type) ?? [])[0]?.({ type, ...event }, this.ctx);
  }

  async emit(type: string, event: Record<string, unknown> = {}, ctx: ExtensionContext = this.ctx): Promise<void> {
    for (const h of this.handlers.get(type) ?? []) await h({ type, ...event }, ctx);
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
/** A tool result message, shaped as pi 1.4.0 stores it. */
function toolResultMessage(toolName: string, content: unknown, details?: unknown, isError = false): ToolResultMessage {
  return { role: "toolResult", toolCallId: `call_${entrySeq++}`, toolName, content, details, isError, timestamp: 0 } as ToolResultMessage;
}

/** A session entry for a tool result. */
function toolResultEntry(toolName: string, content: unknown, details?: unknown, isError = false): SessionEntry {
  return {
    type: "message",
    id: `e${entrySeq++}`,
    parentId: null,
    timestamp: new Date(0).toISOString(),
    message: toolResultMessage(toolName, content, details, isError),
  } as unknown as SessionEntry;
}

/** A pi session entry of any type, for shapes the flat helpers above don't build. */
const entry = (e: Record<string, unknown>): SessionEntry => ({ parentId: null, timestamp: new Date(0).toISOString(), ...e }) as unknown as SessionEntry;

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

  it("refusesExpiredClientMaterialAndWarnsNearExpiry", async () => {
    // an expired keyring: refused at startup, naming the file and the fix, with refused_start
    const expired = resignDemo(demo, join(tmp, `expired-${n++}`), { clientKeyring: Date.now() - 1 });
    const bad = setup([], { clientDir: join(expired, "client") });
    await expect(bad.pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/Paztport refused to start: .*keyring\.json expired at .*npm run setup-demo -- --force/);
    expect(bad.pi.registrations).toEqual([]);
    expect(records(bad.eventsPath)).toEqual([expect.objectContaining({ type: "refused_start", code: "CLIENT_MATERIAL" })]);
    // a root an hour from its notAfter: it starts, and the user is shown one warning naming the file
    const soon = resignDemo(demo, join(tmp, `soon-${n++}`), { clientRoot: Date.now() + 3_600_000 });
    const ok = setup([], { clientDir: join(soon, "client") });
    const notes: [string, string | undefined][] = [];
    const ui = { notify: (m: string, type?: string) => void notes.push([m, type]) };
    await ok.pi.emit("session_start", { reason: "startup" }, { ...ok.pi.ctx, hasUI: true, ui } as unknown as ExtensionContext);
    expect(notes).toEqual([[expect.stringMatching(/^paztport: .*client\/root\.json expires soon \(notAfter \d+ \(.*Z\)\); regenerate the demo keys/), "warning"]]);
    expect(records(ok.eventsPath).filter((e) => e.type === "refused_start")).toEqual([]);
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
    expect([...pi.tools.keys()].sort()).toEqual(["bash", ...GITHUB_TOOLS.map((t) => `mcp__github__${t.name}`), "mcp__docs__fetch_docs"].sort());
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
    expect(before.details.refused).toBe(true);

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
    expect(out.details.refused).toBeUndefined();

    const refused = await pi.execute("mcp__github__create_branch", { ...LIST, branch: "leak" }, id());
    expect(refused.isError).toBe(true);
    expect(refused.content).toEqual([{ type: "text", text: UNSAFE_TEXT }]);
    expect(refused.details.verdict).toBe("INFLUENCE_DENIED");
    expect(refused.details.refused).toBe(true);

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
    expect(pi.registrations).toEqual(["bash", "mcp__docs__fetch_docs"]);
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

  it("restoresBuiltinToolInfluence", async () => {
    // pi emits no tool_result for a call that tool_call blocked (agent-loop.ts prepareToolCall: a block
    // becomes createErrorToolResult(reason) at once), but the session keeps it as an error toolResult
    // holding our refusal text. Restore must record nothing for it; a labelled result keeps its classes.
    const text = (t: string) => [{ type: "text", text: t }];
    const restore = async (branch: SessionEntry[], mode = "enforce") => {
      const s = setup([github(), docs()], { mode });
      s.pi.branch = branch;
      await s.pi.emit("session_start", { reason: "resume" });
      // the docs server is unattested: its live result adds one local-untrusted entry outside off mode
      return (await s.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id())).details.influence;
    };
    const labelled = toolResultEntry("read", text("notes"), { paztport: { labels: ["local-untrusted"] } });
    expect(await restore([labelled])).toEqual({ ...ZERO, "local-untrusted": 2 });
    // a blocked call: the refusal text on an error result, whichever text it was
    for (const t of [UNSAFE_TEXT, SCOPE_TEXT, UNCHECKABLE_TEXT, POLICY_EXPIRED_TEXT]) {
      expect(await restore([toolResultEntry("write", text(t), undefined, true)])).toEqual({ ...ZERO, "local-untrusted": 1 });
      expect(await restore([toolResultEntry("read", text(t), undefined, true)])).toEqual({ ...ZERO, "local-untrusted": 1 });
    }
    // the same text on a result that is not an error, or with more around it, is content
    expect(await restore([toolResultEntry("read", text(SCOPE_TEXT))])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    expect(await restore([toolResultEntry("read", text(`${SCOPE_TEXT} `), undefined, true)])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    // labels come first: a labelled error result with a refusal's text still restores its classes
    expect(await restore([toolResultEntry("read", text(SCOPE_TEXT), { paztport: { labels: ["private"] } }, true)])).toEqual({ ...ZERO, private: 1, "local-untrusted": 1 });
    // nested calls (ctx.executeTool) leave only a record on the parent: their results are unknown
    const nested = { calls: [{ toolName: "read" }], complete: true };
    const parent = toolResultEntry("codemode", text("done"), { paztport: { labels: ["local-untrusted"] } });
    (parent as unknown as { message: Record<string, unknown> }).message.nestedCalls = nested;
    expect(await restore([parent])).toEqual({ ...ZERO, private: 1, "local-untrusted": 3 });
    expect(await restore([parent], "off")).toEqual(ZERO);
    // the same for a foreign tool with an mcp__ name: its nested calls are unknown (private and local-untrusted,
    // the same entry as its own local-untrusted content)
    const mcpParent = toolResultEntry("mcp__other__run", text("done"), { server: "other", tool: "run" });
    (mcpParent as unknown as { message: Record<string, unknown> }).message.nestedCalls = nested;
    expect(await restore([mcpParent])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    expect(await restore([mcpParent], "off")).toEqual({ ...ZERO, "local-untrusted": 1 });
    // unlabelled: it may hold anything
    const unlabelled = toolResultEntry("read", text("notes"));
    expect(await restore([unlabelled])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    expect(await restore([unlabelled], "off")).toEqual(ZERO);
    expect(await restore([labelled], "off")).toEqual(ZERO);
    // write and edit record nothing live, so nothing here
    expect(await restore([toolResultEntry("write", text("ok")), toolResultEntry("edit", text("ok"))])).toEqual({ ...ZERO, "local-untrusted": 1 });
  });

  it("restoredBranchRecordedLikeLivePath", async () => {
    const own = (extra: Record<string, unknown>) => ({ server: "github", callId: id(), influence: ZERO, ...extra });
    const branch = [
      // this extension's results: verified labels are re-recorded as their classes
      toolResultEntry("mcp__github__get_file_contents", [{ type: "text", text: "notes" }], own({ session: "attested", verify: "OK", labels: ["private"] })),
      // unverified, or from an unsafe session: local-untrusted
      toolResultEntry("mcp__github__list_issues", [{ type: "text", text: "issues" }], own({ session: "unsafe", sessionReason: "PIN_MISMATCH" })),
      // a refusal carries no server content and is never recorded
      toolResultEntry("mcp__github__create_branch", [{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }], own({ session: "attested", verdict: "INFLUENCE_DENIED", refused: true }), true),
      // a result the live path recorded is recorded, even with a refusal's text: here an audit verdict
      // from an unsafe session (no labels)
      toolResultEntry("mcp__github__create_branch", [{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }], own({ session: "unsafe", sessionReason: "UNSAFE", verdict: "INFLUENCE_DENIED" })),
      // pi's built-in MCP (details { server, tool }), even under a name this extension registers
      toolResultEntry("mcp__github__list_issues", [{ type: "text", text: "built-in github" }], { server: "github", tool: "list_issues" }),
      toolResultEntry("mcp__other__fetch", [{ type: "text", text: "built-in other" }], { server: "other", tool: "fetch" }),
      toolResultEntry("read_mcp_resource", [{ type: "text", text: "a resource" }], { server: "other", tool: "read_mcp_resource" }),
      toolResultEntry("mcp__other__empty", undefined),
      // a built-in result with no labels: it may hold anything (private and local-untrusted)
      toolResultEntry("bash", [{ type: "text", text: "local output" }]),
      { type: "message", id: "u", parentId: null, timestamp: new Date(0).toISOString(), message: { role: "user", content: "hi", timestamp: 0 } } as unknown as SessionEntry,
      { type: "model_change", id: "m", parentId: null, timestamp: new Date(0).toISOString(), provider: "p", modelId: "m" } as SessionEntry,
    ];

    const enforce = setup([github(), docs()]);
    enforce.pi.branch = branch;
    await enforce.pi.emit("session_start", { reason: "reload" });
    // two unsafe results of ours, four built-in MCP results and the unlabelled bash result (private
    // too), plus the live docs result (the docs server is unattested)
    const a = await enforce.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id());
    expect(a.details.influence).toEqual({ ...ZERO, private: 2, "local-untrusted": 8 });

    // off mode records none of this extension's results (restored or live); the four built-in MCP
    // results still count
    const off = setup([github(), docs()], { mode: "off" });
    off.pi.branch = branch;
    await off.pi.emit("session_start", { reason: "resume" });
    const b = await off.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id());
    expect(b.details.influence).toEqual({ ...ZERO, "local-untrusted": 4 });

    // a local error is not recorded either, as live: only the live docs result counts
    const local = setup([github(), docs()]);
    local.pi.branch = [toolResultEntry("mcp__github__list_issues", [{ type: "text", text: 'MCP server "github" error: not connected' }], own({ session: "attested", refused: true }), true)];
    await local.pi.emit("session_start", { reason: "reload" });
    const c = await local.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id());
    expect(c.details.influence).toEqual({ ...ZERO, "local-untrusted": 1 });
  });

  it("branchSummaryCarriesAbandonedInfluence", async () => {
    // /tree with a summary leaves the branch it abandons off the restored path, but its summary is in
    // context: the abandoned branch's results count on restore.
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const live = new Map<string, Result>();
    for (const [tool, args] of [["list_issues", LIST], ["get_file_contents", PAYROLL]] as const) {
      live.set(tool, await pi.execute(`mcp__github__${tool}`, args, id()));
    }
    const append = (sm: SessionManager, tool: string) => {
      const r = live.get(tool)!;
      return sm.appendMessage(toolResultMessage(`mcp__github__${tool}`, r.content, r.details));
    };
    /** A real pi session whose path is a prompt and a summary of an abandoned branch holding these results. */
    const summarised = (tools: string[]): SessionManager => {
      const sm = SessionManager.inMemory(workspace);
      const root = sm.appendMessage({ role: "user", content: "fix the typo", timestamp: 0 });
      for (const tool of tools) append(sm, tool);
      sm.branchWithSummary(root, "Read the issues and the payroll notes.");
      expect(sm.getBranch().map((e) => e.type)).toEqual(["message", "branch_summary"]);
      return sm;
    };
    const write = async (sm: SessionManager, branch: string): Promise<Result> => {
      pi.session = sm;
      await pi.emit("session_start", { reason: "resume" });
      await pi.prompt("fix the typo");
      return pi.execute("mcp__github__create_branch", { ...LIST, branch }, id());
    };

    // the payroll notes were read on the abandoned branch: poisoned
    const poisoned = await write(summarised(["list_issues", "get_file_contents"]), "leak-1");
    expect(poisoned.details.verdict).toBe("INFLUENCE_DENIED");
    expect(poisoned.details.influence).toEqual({ ...ZERO, "third-party": 1, private: 1 });
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED" });

    // only the issues: the write is allowed, and its influence is exactly what the branch held
    const clean = await write(summarised(["list_issues"]), "fix-1");
    expect(clean.isError).toBe(false);
    expect(clean.details.influence).toEqual({ ...ZERO, "third-party": 1, public: 1 });
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "ALLOWED" });

    // nested: the abandoned branch holds a summary of a branch abandoned before it
    const nested = SessionManager.inMemory(workspace);
    const root = nested.appendMessage({ role: "user", content: "fix the typo", timestamp: 0 });
    append(nested, "get_file_contents");
    nested.branchWithSummary(root, "Read the payroll notes.");
    append(nested, "list_issues");
    nested.branchWithSummary(root, "Read the issues.");
    const deep = await write(nested, "leak-2");
    expect(deep.details.verdict).toBe("INFLUENCE_DENIED");
    expect(deep.details.influence).toEqual({ ...ZERO, "third-party": 1, private: 1 });

    // compaction summarises entries on the path itself, which restore already walks
    const compacted = SessionManager.inMemory(workspace);
    compacted.appendMessage({ role: "user", content: "fix the typo", timestamp: 0 });
    append(compacted, "get_file_contents");
    append(compacted, "list_issues");
    const kept = compacted.appendMessage({ role: "user", content: "go on", timestamp: 0 });
    compacted.appendCompaction("Read the payroll notes and the issues.", kept, 1000);
    const afterCompaction = await write(compacted, "leak-3");
    expect(afterCompaction.details.verdict).toBe("INFLUENCE_DENIED");
  });

  it("unresolvableBranchSummaryCountsAsPrivate", async () => {
    const own = (extra: Record<string, unknown>) => ({ server: "github", callId: id(), influence: ZERO, session: "attested", ...extra });
    /** Restores a real pi session holding these entries (the last is the leaf) and reads the influence. */
    const restore = async (entries: SessionEntry[], mode = "enforce") => {
      const s = setup([github(), docs()], { mode });
      s.pi.session = SessionManager.inMemory(workspace, undefined, entries);
      await s.pi.emit("session_start", { reason: "resume" });
      // the docs server is unattested: its live result adds one local-untrusted entry outside off mode
      return (await s.pi.execute("mcp__docs__fetch_docs", { page: "contributing" }, id())).details.influence;
    };
    const user = entry({ type: "message", id: "u", message: { role: "user", content: "hi", timestamp: 0 } });
    const summary = (fromId: unknown) => entry({ type: "branch_summary", id: "s", parentId: "u", ...(fromId !== undefined ? { fromId } : {}), summary: "Read the payroll notes." });

    // An unresolvable summary may stand for anything, private content included: it counts as private
    // and local-untrusted. fromId names an entry this session does not hold (e.g. a session cut down
    // to one path, with no parent file to look in)
    const gone = [user, summary("gone")];
    expect(await restore(gone)).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    // pi's fromId for a summary made with no leaf, and no fromId at all
    expect(await restore([user, summary("root")])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });
    expect(await restore([user, summary(undefined)])).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });

    // a broken chain: what resolves is recorded, and the summary too
    const notes = { ...toolResultEntry("mcp__github__get_file_contents", [{ type: "text", text: "notes" }], own({ verify: "OK", labels: ["private"] })), id: "a", parentId: "missing" } as SessionEntry;
    const broken = [notes, user, summary("a")];
    expect(await restore(broken)).toEqual({ ...ZERO, private: 2, "local-untrusted": 2 });

    // a parent chain that loops, reachable only from fromId: restore ends, and the summary counts
    const loop = [
      entry({ type: "message", id: "a", parentId: "b", message: { role: "user", content: "a", timestamp: 0 } }),
      entry({ type: "message", id: "b", parentId: "a", message: { role: "user", content: "b", timestamp: 0 } }),
      user,
      summary("a"),
    ];
    expect(await restore(loop)).toEqual({ ...ZERO, private: 1, "local-untrusted": 2 });

    // and a public write on such a context is refused
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const w = setup([github(outcome)]);
    w.pi.session = SessionManager.inMemory(workspace, undefined, gone);
    await w.pi.emit("session_start", { reason: "resume" });
    await w.pi.prompt("fix the typo");
    const write = await w.pi.execute("mcp__github__create_branch", { ...LIST, branch: "leak" }, id());
    expect(write.details.verdict).toBe("INFLUENCE_DENIED");
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED" });

    // off mode records none of this
    expect(await restore(gone, "off")).toEqual(ZERO);
    expect(await restore(broken, "off")).toEqual(ZERO);
  });

  it("forkedSessionResolvesSummaryThroughParent", async () => {
    // /fork and /clone write only the current path to a new session file, naming the old file in the
    // header's parentSession: a summary's abandoned branch is looked up there.
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const live = new Map<string, Result>();
    for (const [tool, args] of [["list_issues", LIST], ["get_file_contents", PAYROLL]] as const) {
      live.set(tool, await pi.execute(`mcp__github__${tool}`, args, id()));
    }
    /** A persisted pi session: a prompt, an abandoned branch with these results, a summary; then forked. */
    const forked = (tools: string[]): { sm: SessionManager; dir: string; parent: string } => {
      const dir = join(tmp, `sessions-${n++}`);
      const sm = SessionManager.create(workspace, dir);
      const root = sm.appendMessage({ role: "user", content: "fix the typo", timestamp: 0 });
      for (const tool of tools) {
        const r = live.get(tool)!;
        sm.appendMessage(toolResultMessage(`mcp__github__${tool}`, r.content, r.details));
      }
      sm.branchWithSummary(root, "Read the issues and the payroll notes.");
      const parent = sm.getSessionFile()!;
      const file = sm.createBranchedSession(sm.getLeafId()!)!;
      expect(file).not.toBe(parent);
      expect(sm.getHeader()?.parentSession).toBe(parent);
      expect(sm.getEntries().map((e) => e.type)).toEqual(["message", "branch_summary"]); // the path alone
      return { sm: SessionManager.open(file, dir), dir, parent };
    };
    const write = async (sm: SessionManager, branch: string): Promise<Result> => {
      pi.session = sm;
      await pi.emit("session_start", { reason: "fork" });
      await pi.prompt("fix the typo");
      return pi.execute("mcp__github__create_branch", { ...LIST, branch }, id());
    };

    // resolved through the parent: exactly the abandoned branch's classes
    const poisoned = await write(forked(["list_issues", "get_file_contents"]).sm, "leak-1");
    expect(poisoned.details.verdict).toBe("INFLUENCE_DENIED");
    expect(poisoned.details.influence).toEqual({ ...ZERO, "third-party": 1, private: 1 });
    const clean = await write(forked(["list_issues"]).sm, "fix-1");
    expect(clean.isError).toBe(false);
    expect(clean.details.influence).toEqual({ ...ZERO, "third-party": 1, public: 1 });

    // the parent is gone: the summary counts as private and local-untrusted, and the write is refused
    const gone = forked(["list_issues"]);
    rmSync(gone.parent);
    const denied = await write(gone.sm, "leak-2");
    expect(denied.details.verdict).toBe("INFLUENCE_DENIED");
    expect(denied.details.influence).toEqual({ ...ZERO, private: 1, "local-untrusted": 1 });

    // a parent outside this session's directory is not read
    const elsewhere = forked(["list_issues"]);
    const other = join(tmp, `sessions-${n++}`);
    mkdirSync(other);
    const outside = await write(SessionManager.open(elsewhere.sm.getSessionFile()!, other), "leak-3");
    expect(outside.details.verdict).toBe("INFLUENCE_DENIED");
    expect(outside.details.influence).toEqual({ ...ZERO, private: 1, "local-untrusted": 1 });
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "INFLUENCE_DENIED" });
  });

  it("supersededSessionStartLeavesStateAlone", async () => {
    const outcome = join(tmp, `outcome-${n++}.jsonl`);
    const { pi } = setup([github(outcome)]);
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const poisoned = SessionManager.inMemory(workspace);
    for (const [tool, args] of [["list_issues", LIST], ["get_file_contents", PAYROLL]] as const) {
      const out = await pi.execute(`mcp__github__${tool}`, args, id());
      poisoned.appendMessage(toolResultMessage(`mcp__github__${tool}`, out.content, out.details));
    }
    const ctx = (sessionManager: SessionManager) => ({ ...pi.ctx, sessionManager }) as ExtensionContext;

    // two session_starts overlap: the earlier is still closing the running server when the later
    // starts, so the later restores and connects first. The earlier must not reset or restore over it.
    const earlier = pi.emit("session_start", { reason: "resume" }, ctx(poisoned));
    const later = pi.emit("session_start", { reason: "new" }, ctx(SessionManager.inMemory(workspace)));
    await Promise.all([earlier, later]);
    await until(() => running(outcome) === 1);

    await pi.prompt("fix the typo");
    const write = await pi.execute("mcp__github__create_branch", { ...LIST, branch: "fix" }, id());
    // the earlier start's RunState would leave the later's connections with no active run
    expect(write.isError, JSON.stringify(write.content)).toBe(false);
    expect(write.details.influence).toEqual({ ...ZERO, public: 1 }); // the later, empty branch
    expect(records(outcome).at(-1)).toMatchObject({ tool: "create_branch", verdict: "ALLOWED" });
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
    expect(out.details.refused).toBe(true);
    await pi.emit("session_shutdown", { reason: "quit" }); // idempotent
  });
});

describe("local gate wiring", { timeout: 30_000 }, () => {
  /** A workspace with the demo folders and both logs inside its public folder, to tell "refused" from "outside". */
  function local(mode = "enforce") {
    const cwd = join(tmp, `local-ws-${n++}`);
    mkdirSync(join(cwd, "website"), { recursive: true });
    writeFileSync(join(cwd, "website", "README.md"), "# Acme\n");
    const eventsLog = join(cwd, "website", "events.jsonl");
    const evidenceLog = join(cwd, "website", "evidence.jsonl");
    const raw = JSON.stringify({ mode, clientDir: join(demo, "client"), clientPolicyDir: join(demo, "client/local-tools"), servers: [], eventsLog, evidenceLog });
    const { pi } = setup([], { cwd, raw });
    return { pi, eventsLog, evidenceLog };
  }
  const toolCall = (pi: FakePi, toolName: string, input: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
    pi.call("tool_call", { toolName, toolCallId: id(), input, ...extra });

  it("gatesBuiltinsAndRefusesOwnFiles", async () => {
    const { pi, evidenceLog } = local();
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    expect(await toolCall(pi, "read", { path: "website/README.md" })).toBeUndefined();
    expect(await toolCall(pi, "read", { path: "website/events.jsonl" })).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(await toolCall(pi, "read", { path: "website/evidence.jsonl" })).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(await toolCall(pi, "ls", { path: "website" })).toEqual({ block: true, reason: SCOPE_TEXT });
    // a call another tool made is checked the same way
    expect(await toolCall(pi, "read", { path: "website/events.jsonl" }, { parentToolCallId: "toolu_parent" })).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(await toolCall(pi, "read", { path: "website/README.md" }, { parentToolCallId: "toolu_parent" })).toBeUndefined();
    const evidence = records(evidenceLog);
    expect(evidence.map((r) => r.type)).toEqual(["client", "run", "local", "local", "local", "local", "local", "local"]);
    expect(evidence.filter((r) => r.type === "local").map((r) => r.verdict)).toEqual(["OK", "SCOPE_DENIED", "SCOPE_DENIED", "SCOPE_DENIED", "SCOPE_DENIED", "OK"]);
  });

  it("toolResultRecordsLabels", async () => {
    const { pi } = local();
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    const readId = id();
    expect(await pi.call("tool_call", { toolName: "read", toolCallId: readId, input: { path: "website/README.md" } })).toBeUndefined();
    const result = { toolName: "read", input: {}, content: [{ type: "text", text: "# Acme" }], isError: false };
    expect(await pi.call("tool_result", { ...result, toolCallId: readId, details: { truncation: 1 } })).toEqual({
      details: { truncation: 1, paztport: { labels: ["public"] } },
    });
    // labels are taken once; a write records nothing
    expect(await pi.call("tool_result", { ...result, toolCallId: readId, details: undefined })).toBeUndefined();
    const writeId = id();
    expect(await pi.call("tool_call", { toolName: "write", toolCallId: writeId, input: { path: "website/x.md", content: "x" } })).toBeUndefined();
    expect(await pi.call("tool_result", { ...result, toolName: "write", toolCallId: writeId, details: undefined })).toBeUndefined();
  });

  it("offModeDoesNotGate", async () => {
    const { pi, evidenceLog } = local("off");
    await pi.emit("session_start", { reason: "startup" });
    await pi.prompt("fix the typo");
    expect(await toolCall(pi, "read", { path: "website/events.jsonl" })).toBeUndefined();
    expect(records(evidenceLog).map((r) => r.type)).toEqual(["run"]);
  });

  it("failedStartRefusesEveryCall", async () => {
    const { pi } = setup([], { raw: "{ not json" });
    await expect(pi.emit("session_start", { reason: "startup" })).rejects.toThrow(/refused to start/);
    expect(await toolCall(pi, "read", { path: "README.md" })).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(await toolCall(pi, "mcp__other__x", {})).toEqual({ block: true, reason: SCOPE_TEXT });
  });

  it("throwAfterPrepareRefusesEveryCall", async () => {
    // Steps after the config loads can throw too (restoring influence from the branch, reading pi's
    // session folder). The evidence log cannot be used for this: its writes are best effort and never throw.
    for (const broken of ["getBranch", "getSessionDir"] as const) {
      const { pi } = local();
      const sessionManager = { ...pi.ctx.sessionManager, [broken]: () => { throw new Error(`${broken} failed`); } };
      await expect(pi.emit("session_start", { reason: "startup" }, { ...pi.ctx, sessionManager } as ExtensionContext)).rejects.toThrow(`${broken} failed`);
      await pi.prompt("fix the typo");
      expect(await toolCall(pi, "read", { path: "website/README.md" })).toEqual({ block: true, reason: SCOPE_TEXT });
      expect(await toolCall(pi, "bash", { command: "cat website/README.md" })).toEqual({ block: true, reason: SCOPE_TEXT });
    }
  });

  it("aGatedBashThatFailsToRegisterLeavesEveryCallRefused", async () => {
    const { pi } = local();
    pi.throwOn.add("bash");
    await expect(pi.emit("session_start", { reason: "startup" })).rejects.toThrow("cannot register bash");
    await pi.prompt("fix the typo");
    expect(await toolCall(pi, "read", { path: "website/README.md" })).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(await toolCall(pi, "bash", { command: "cat website/README.md" })).toEqual({ block: true, reason: SCOPE_TEXT });
  });

  it("unresolvableRefusedEntryIsKept", async () => {
    // a refused folder that cannot be resolved (here a symlink loop) is kept, so nothing can be checked
    const { pi } = local();
    const loop = join(tmp, `loop-${n++}`);
    symlinkSync(loop, loop);
    const sessionManager = { ...pi.ctx.sessionManager, getSessionDir: () => loop };
    await pi.emit("session_start", { reason: "startup" }, { ...pi.ctx, sessionManager } as ExtensionContext);
    await pi.prompt("fix the typo");
    expect(await toolCall(pi, "read", { path: "website/README.md" })).toEqual({ block: true, reason: UNCHECKABLE_TEXT });
  });

  it("openSessionFileIsRefused", async () => {
    const { pi } = local();
    // inside the public folder, so only the refusal can stop a read of it
    const file = join(pi.ctx.cwd, "website", "session.jsonl");
    writeFileSync(file, "{}\n");
    const sessionManager = { ...pi.ctx.sessionManager, getSessionFile: () => file };
    await pi.emit("session_start", { reason: "startup" }, { ...pi.ctx, sessionManager } as ExtensionContext);
    await pi.prompt("fix the typo");
    expect(await toolCall(pi, "read", { path: "website/session.jsonl" })).toEqual({ block: true, reason: SCOPE_TEXT });
  });

  it("noConfigDoesNotGate", async () => {
    const pi = new FakePi({}, workspace);
    paztport(pi.api);
    started.push(pi);
    await pi.emit("session_start", { reason: "startup" });
    expect(await toolCall(pi, "bash", { command: "curl x" })).toBeUndefined();
  });
});
