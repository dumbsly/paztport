// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { resolve } from "node:path";
import type { Tool } from "@earendil-works/pi-mcp";
import type { InfluenceClass } from "@paztport/core";
import {
  getAgentDir,
  type AgentToolResult,
  type ExtensionAPI,
  type ExtensionContext,
  type SessionEntry,
  type ToolAnnotations,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { assertOutsideWorkspace, loadConfig, resolveConfigPath, type PaztportConfig } from "./config.ts";
import { ServerConnection, type CallOutcome } from "./connection.ts";
import { EventLog } from "./events.ts";
import { clientRecord, EvidenceLog } from "./evidence.ts";
import { contentHash, InfluenceStore } from "./influence.ts";
import { loadClientMaterial, type ClientMaterial } from "./keys.ts";
import { LocalGate } from "./local/gate.ts";
import { canonical } from "./local/paths.ts";
import { createGatedBash } from "./local/shell.ts";
import { isRefusalText, SCOPE_TEXT } from "./refusals.ts";
import { SessionChain, type SessionView } from "./restore.ts";
import { RunState } from "./runs.ts";

const FLAG = "paztport-config";
/** Provider tool names are limited to 64 characters. */
const MAX_TOOL_NAME = 64;
/** pi's built-in MCP resource tools; like its `mcp__` tools they return MCP server content. */
const BUILTIN_MCP_RESOURCE_TOOLS = new Set(["list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource"]);
const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;
/** A Record, so tsc flags a class added to the library and missing here. */
const CLASSES: Record<InfluenceClass, true> = { "third-party": true, private: true, public: true, "local-untrusted": true };

/** Tools whose results carry MCP server content: `mcp__` tools (this extension's and pi's built-in MCP) and pi's MCP resource tools. */
const isMcpTool = (name: string): boolean => name.startsWith("mcp__") || BUILTIN_MCP_RESOURCE_TOOLS.has(name);

type Details = CallOutcome["details"] | { server: string; influence: Record<string, number>; refused: true };
type Parameters = ToolDefinition["parameters"];

const sanitise = (s: string): string => s.replace(/[^A-Za-z0-9_]/g, "_");

/**
 * `mcp__<server>__<tool>` with everything but `[A-Za-z0-9_]` replaced by `_`, like pi's built-in MCP
 * tools. A name over 64 characters, or one already taken by a different tool, is cut and given a
 * hash suffix of the unsanitised pair, as pi does.
 */
export function mcpToolName(server: string, tool: string, isTaken: (name: string) => boolean = () => false): string {
  const name = sanitise(`mcp__${server}__${tool}`);
  if (name.length <= MAX_TOOL_NAME && !isTaken(name)) {
    return name;
  }
  const hash = createHash("sha256").update(`${server}\0${tool}`).digest("hex").slice(0, 8);
  return `${name.slice(0, MAX_TOOL_NAME - hash.length - 1)}_${hash}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The remote inputSchema with `type` forced to "object": MCP requires it, and a tool declared with
 * another type would make every provider request invalid.
 */
function parametersOf(tool: Tool): Parameters {
  const schema = isObject(tool.inputSchema) ? tool.inputSchema : {};
  return { ...schema, type: "object" } as unknown as Parameters;
}

/** The MCP behaviour hints pi knows; MCP's annotation `title` is not one. */
function annotationsOf(tool: Tool): ToolAnnotations | undefined {
  const a = tool.annotations;
  if (!isObject(a)) {
    return undefined;
  }
  const out: ToolAnnotations = {};
  for (const k of HINTS) {
    if (typeof a[k] === "boolean") {
      out[k] = a[k];
    }
  }
  return out;
}

/**
 * Hash of a tool result's content as pi holds it. Content JCS rejects (a lone surrogate, or none at
 * all) is hashed through its JSON text instead, so it is still recorded.
 */
function hashContent(content: unknown): string {
  try {
    return contentHash({ content });
  } catch {
    return contentHash({ content: [{ type: "text", text: JSON.stringify(content ?? null) }] });
  }
}

const text = (t: string) => [{ type: "text" as const, text: t }];

/** The influence classes in a restored result's details.labels, or undefined if they are not a list of classes. */
function classesOf(labels: unknown): InfluenceClass[] | undefined {
  if (!Array.isArray(labels) || !labels.every((l) => typeof l === "string" && Object.hasOwn(CLASSES, l))) {
    return undefined;
  }
  return labels as InfluenceClass[];
}

/**
 * Canonical paths no local tool call may touch: the config, the client keys and policy, the pins, the
 * logs, pi's session folder and pi's agent folder. A path canonical() cannot resolve (a dangling link,
 * no permission) is kept as resolved: the gate then finds every path uncheckable, which fails closed.
 */
function refusedPaths(path: string, config: PaztportConfig, ctx: ExtensionContext): string[] {
  const sm = ctx.sessionManager as Partial<ExtensionContext["sessionManager"]>;
  const sessionDir = typeof sm.getSessionDir === "function" ? sm.getSessionDir() : undefined;
  const all = [
    path,
    config.clientDir,
    config.clientPolicyDir,
    ...config.servers.map((s) => s.pin),
    config.eventsLog,
    config.evidenceLog,
    sessionDir,
    // with --session <file> and --session-dir, the open file need not be under the folder
    typeof sm.getSessionFile === "function" ? sm.getSessionFile() : undefined,
    getAgentDir(),
  ];
  const out: string[] = [];
  for (const p of all) {
    // an in-memory session has "" for its folder, which would resolve to the cwd
    if (typeof p !== "string" || p === "") {
      continue;
    }
    try {
      out.push(canonical(p));
    } catch {
      out.push(resolve(p));
    }
  }
  return out;
}

/**
 * Makes pi a Paztport harness for the MCP servers named in the config (--paztport-config or
 * PAZTPORT_CONFIG): their tools are registered as `mcp__<server>__<tool>` and every call goes
 * through a {@link ServerConnection}. Every other tool call, pi's built-in tools included, is checked
 * by a {@link LocalGate} against the signed client rules. Without a config the extension does nothing;
 * with a config that fails to load, every tool call but this extension's is refused.
 */
export default function paztport(pi: ExtensionAPI): void {
  pi.registerFlag(FLAG, { description: "Path to the Paztport config (JSON); overrides PAZTPORT_CONFIG", type: "string" });

  const influence = new InfluenceStore();
  let runs = new RunState();
  let connections = new Map<string, ServerConnection>();
  /** The evidence file of the current session; a no-op log until a config is loaded. */
  let evidence = new EvidenceLog(undefined);
  /** Checks every tool call but this extension's MCP calls; undefined without a config. */
  let gate: LocalGate | undefined;
  /** A config was named and the session is not set up yet (or failed to): every call the gate would check is refused. */
  let failedStart = false;
  /** Every tool name this extension registered, to its server id and remote tool name. */
  const registered = new Map<string, { server: string; tool: string }>();
  /**
   * pi toolCallIds this extension's execute ran, until tool_result sees them. pi passes the same id
   * to execute and tool_result, and tool_result only follows an execute. Names alone cannot tell
   * these results apart: pi's built-in MCP may register the same `mcp__<id>__<tool>` name.
   */
  const ownCalls = new Set<string>();
  /**
   * Bumped by session_start and session_shutdown, so a superseded start drops its connections.
   * pi 1.4.0 builds a fresh runtime and extension instance per session switch or reload (after
   * session_shutdown), so the reconnect path here is defensive (R13).
   */
  let generation = 0;

  async function closeAll(): Promise<void> {
    const open = [...connections.values()];
    connections = new Map();
    await Promise.all(open.map((c) => c.close()));
  }

  async function execute(name: string, params: unknown, toolCallId: string): Promise<AgentToolResult<Details>> {
    ownCalls.add(toolCallId);
    const target = registered.get(name);
    const server = target?.server ?? name;
    const conn = target !== undefined ? connections.get(target.server) : undefined;
    if (target === undefined || conn === undefined) {
      return { content: text(`MCP server "${server}" is not connected`), details: { server, influence: influence.summary(), refused: true }, isError: true };
    }
    const out = await conn.call(target.tool, isObject(params) ? params : {}, toolCallId);
    return { content: text(out.text), details: out.details, isError: out.isError };
  }

  function register(serverId: string, tool: Tool): void {
    const taken = (n: string) => {
      const r = registered.get(n);
      return r !== undefined && (r.server !== serverId || r.tool !== tool.name);
    };
    const name = mcpToolName(serverId, tool.name, taken);
    const annotations = annotationsOf(tool);
    pi.registerTool({
      name,
      label: tool.title ?? tool.annotations?.title ?? tool.name,
      description: tool.description ?? "",
      parameters: parametersOf(tool),
      ...(annotations !== undefined ? { annotations } : {}),
      namespace: { name: sanitise(`mcp__${serverId}`), aliases: [serverId] },
      execute: (toolCallId, params) => execute(name, params, toolCallId),
    });
    registered.set(name, { server: serverId, tool: tool.name });
  }

  /**
   * Records one restored built-in tool result as the live tool_result did. Off mode records nothing.
   * Labels in details.paztport give their classes (the source is local:<tool>, as live). pi emits no
   * tool_result for a call that tool_call blocked: it saves an error result holding our refusal text, which
   * is not recorded. write and edit record nothing live. Any other result has no labels (this
   * extension did not see it, or it came from another run) and may hold anything: private and
   * local-untrusted. A result with nested calls has had them recorded by restoreEntry, and records nothing more
   * unless it has labels.
   */
  function restoreLocal(toolName: string, m: Record<string, unknown>, mode: PaztportConfig["mode"], nested: boolean): void {
    if (mode === "off") {
      return;
    }
    const d = m.details;
    const p = isObject(d) ? d.paztport : undefined;
    const classes = isObject(p) ? classesOf(p.labels) : undefined;
    const hash = hashContent(m.content);
    if (classes !== undefined) {
      influence.recordClasses(`local:${toolName}`, classes, hash);
      return;
    }
    if (nested || (m.isError === true && isRefusalText(m.content)) || toolName === "write" || toolName === "edit") {
      return;
    }
    influence.recordUnknown(`builtin:${toolName}`, hash);
  }

  /** Records one restored tool result as the live path did; any other entry records nothing. */
  function restoreEntry(entry: SessionEntry, ids: Set<string>, mode: PaztportConfig["mode"]): void {
    if (entry.type !== "message") {
      return;
    }
    const m: unknown = entry.message;
    if (!isObject(m) || m.role !== "toolResult" || typeof m.toolName !== "string") {
      return;
    }
    const d = m.details;
    const nested = isObject(m.nestedCalls) && (m.nestedCalls.complete === false || (Array.isArray(m.nestedCalls.calls) && m.nestedCalls.calls.length > 0));
    if (nested && mode !== "off") {
      // pi saves no result for a nested call (ctx.executeTool), only this record on the parent, so what the
      // nested calls returned (any built-in or MCP tool) is unknown, whatever the parent's name
      influence.recordUnknown(`builtin:${m.toolName}`, hashContent(m.content));
    }
    if (!isMcpTool(m.toolName)) {
      restoreLocal(m.toolName, m, mode, nested);
      return;
    }
    if (isObject(d) && typeof d.server === "string" && ids.has(d.server) && isObject(d.influence)) {
      // details.refused: an outcome the live path recorded nothing for (see CallOutcome)
      if (mode === "off" || d.refused === true) {
        return;
      }
      const classes = classesOf(d.labels);
      if (classes !== undefined) {
        influence.recordClasses(d.server, classes, hashContent(m.content));
      } else {
        influence.recordUntrusted(`server:${d.server}`, hashContent(m.content));
      }
    } else {
      influence.recordUntrusted(`builtin:${m.toolName}`, hashContent(m.content));
    }
  }

  /**
   * Records the influence of the tool results on a restored session branch, as the live path did:
   * pi keeps a session's messages over a reload, and resume, fork and a startup with -c or --session
   * restore them, so what reached the model then is still in its context (R16). Our results (details
   * naming a configured server, with an influence summary) give their label classes, without cids,
   * or local-untrusted when they have no labels; refusals and local errors (details.refused) give
   * nothing, and in off mode none of ours count. Every other MCP or MCP resource result is
   * local-untrusted, as in tool_result.
   *
   * A branch_summary entry (left by /tree) stands in for a branch the path no longer holds, so the
   * entries it summarised count too: the abandoned branch from its fromId, less what is already
   * counted, walked the same way (nested summaries included). It is looked up in this session, then
   * in the sessions it was forked or cloned from (see SessionChain). When it cannot be resolved in
   * full (no such entry, a broken or looping parent chain, an unreadable parent) the summary may hold
   * anything, so it counts as private and local-untrusted. A compaction entry needs none of this: it
   * summarises entries on its own path.
   */
  function restoreInfluence(session: SessionView, config: PaztportConfig): void {
    const ids = new Set(config.servers.map((spec) => spec.id));
    const chain = new SessionChain(session);
    // depth: the session (0 is this one, then its parents) an entry was found in
    const work = session.getBranch().map((entry) => ({ entry, depth: 0 }));
    const seen = new Set(work.map((w) => w.entry.id));
    // work grows as abandoned branches are found
    for (let i = 0; i < work.length; i++) {
      const { entry, depth } = work[i]!;
      restoreEntry(entry, ids, config.mode);
      if (entry.type !== "branch_summary") {
        continue;
      }
      const abandoned = chain.branch(entry.fromId, depth);
      // Off mode records none of this extension's results, so an unresolvable summary records
      // nothing either, while built-in MCP results on a resolved branch still count (as on the path
      // and live). Harmless: off mode sends no influence to any server.
      if (!abandoned.complete && config.mode !== "off") {
        influence.recordUnknown("local:branch_summary", hashContent([{ type: "text", text: entry.summary }]));
      }
      for (const e of abandoned.entries) {
        if (!seen.has(e.id)) {
          seen.add(e.id);
          work.push({ entry: e, depth: abandoned.depth });
        }
      }
    }
  }

  /** Loads the config, guards the workspace and loads the keys; throws (after any refused_start) if any fails. */
  function prepare(
    path: string,
    ctx: ExtensionContext,
  ): { config: PaztportConfig; events: EventLog; evidence: EvidenceLog; material: ClientMaterial } {
    let events: EventLog | undefined;
    let code = "CONFIG";
    try {
      const config = loadConfig(path);
      code = "WORKSPACE_GUARD";
      // R14: a config inside the workspace is the agent's to edit, so its eventsLog is not used either
      assertOutsideWorkspace(path, ctx.cwd, "config");
      code = "EVENTS_LOG";
      events = new EventLog(config.eventsLog);
      code = "EVIDENCE_LOG";
      const evidenceLog = new EvidenceLog(config.evidenceLog);
      code = "WORKSPACE_GUARD";
      assertOutsideWorkspace(config.clientDir, ctx.cwd);
      if (config.clientPolicyDir !== undefined) {
        assertOutsideWorkspace(config.clientPolicyDir, ctx.cwd, "clientPolicyDir");
      }
      for (const spec of config.servers) {
        if (spec.pin !== undefined) {
          // a missing pin leaves the server unsafe (PIN_MISSING); it is judged by where it would be
          assertOutsideWorkspace(spec.pin, ctx.cwd, `servers.${spec.id}.pin`, { mayBeMissing: true });
        }
      }
      code = "CLIENT_MATERIAL";
      // a keyring or root near its notAfter: one warning line each, shown to the user (stderr without a UI)
      const warn = (message: string) => (ctx.hasUI ? ctx.ui.notify(message, "warning") : console.error(message));
      const material = loadClientMaterial(config.clientDir, config.clientPolicyDir, Date.now(), warn);
      return { config, events, evidence: evidenceLog, material };
    } catch (e) {
      events?.emit({ type: "refused_start", code });
      throw new Error(`Paztport refused to start: ${(e as Error).message}`);
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    const gen = ++generation;
    await closeAll();
    if (gen !== generation) {
      // a later session_start or session_shutdown superseded this one while it closed the old
      // connections: the influence, runs and connections are the later one's to set up
      return;
    }
    influence.reset();
    ownCalls.clear();
    runs = new RunState();
    evidence = new EvidenceLog(undefined);
    gate = undefined;
    failedStart = false;
    const flag = pi.getFlag(FLAG);
    const path = resolveConfigPath(typeof flag === "string" ? flag : undefined, process.env);
    if (path === undefined) {
      return;
    }
    // fail closed until the gate is built and influence restored: a throw on the way must not leave
    // pi's own tools ungated
    failedStart = true;
    const prepared = prepare(path, ctx);
    const { config, events, material } = prepared;
    evidence = prepared.evidence;
    if (config.mode === "enforce") {
      evidence.write(clientRecord(material));
    }
    gate = new LocalGate({
      mode: config.mode,
      material,
      influence,
      runs,
      events,
      evidence,
      now: Date.now,
      workspace: ctx.cwd,
      refused: refusedPaths(path, config, ctx),
    });
    // before the tools are registered, so every call this session stamps carries the restored influence
    restoreInfluence(ctx.sessionManager, config);
    if (config.mode !== "off") {
      // pi's own bash is replaced by one with a fixed shell, PATH and environment (mode off keeps pi's);
      // before failedStart is cleared, so a registration that throws leaves pi's own tools refused
      pi.registerTool(createGatedBash(ctx.cwd));
    }
    failedStart = false;
    const fresh = config.servers.map((spec) => new ServerConnection(spec, config.mode, material, influence, runs, events, Date.now, evidence));
    const results = await Promise.allSettled(fresh.map((c) => c.connect()));
    if (gen !== generation) {
      // a later session_start or session_shutdown superseded this one
      await Promise.all(fresh.map((c) => c.close()));
      return;
    }
    const failed: string[] = [];
    config.servers.forEach((spec, i) => {
      const result = results[i]!;
      if (result.status === "rejected") {
        // connect() emitted CONNECT_FAILED; with no tool list there is nothing to register
        failed.push((result.reason as Error).message);
        return;
      }
      connections.set(spec.id, fresh[i]!);
      for (const tool of fresh[i]!.tools()) {
        try {
          register(spec.id, tool);
        } catch (e) {
          failed.push(`MCP server "${spec.id}" tool "${tool.name}" was not registered: ${(e as Error).message}`);
        }
      }
    });
    if (failed.length > 0) {
      throw new Error(`Paztport: ${failed.join("; ")}`);
    }
  });

  pi.on("before_agent_start", (event) => {
    if (event.messageType === "user") {
      const ts = Date.now();
      try {
        runs.start(event.prompt, ts);
      } catch {
        // Any failure to start the run, such as a prompt that cannot be bound (a lone surrogate), starts no run:
        // the turn's signed calls fail as with no run.
        runs.clear();
      }
      const run = runs.current();
      if (run !== undefined) {
        evidence.write({ v: 1, type: "run", rid: run.rid, ts, prompt: event.prompt });
      }
    }
  });

  // Every call but this extension's MCP calls, including calls a tool makes itself (parentToolCallId):
  // pi emits tool_call for those too, and they are checked the same way.
  pi.on("tool_call", (event) => {
    if (registered.has(event.toolName)) {
      return undefined; // its ServerConnection stamps and the server checks it
    }
    if (failedStart) {
      return { block: true, reason: SCOPE_TEXT };
    }
    if (gate === undefined) {
      return undefined;
    }
    const r = gate.check(event.toolName, isObject(event.input) ? event.input : {}, event.toolCallId);
    return r.block ? { block: true, reason: r.reason } : undefined;
  });

  pi.on("tool_result", (event) => {
    if (ownCalls.delete(event.toolCallId)) {
      return undefined; // recorded (or not) by its ServerConnection
    }
    const name = event.toolName;
    // taken for every result, so labels of a call whose result is handled below are not kept
    const labels = gate?.labelsFor(event.toolCallId);
    if (isMcpTool(name)) {
      influence.recordUntrusted(`builtin:${name}`, hashContent(event.content));
      return undefined;
    }
    // undefined: refused (pi emits no tool_result for a blocked call), off mode, or no config
    if (labels === undefined || name === "write" || name === "edit") {
      return undefined;
    }
    influence.recordClasses(`local:${name}`, labels, hashContent(event.content));
    return { details: { ...(isObject(event.details) ? event.details : {}), paztport: { labels } } };
  });

  pi.on("session_shutdown", async () => {
    generation++;
    await closeAll();
  });
}
