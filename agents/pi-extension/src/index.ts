// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import type { Tool } from "@earendil-works/pi-mcp";
import type { InfluenceClass } from "@paztport/path-attest";
import type {
  AgentToolResult,
  ExtensionAPI,
  ExtensionContext,
  SessionEntry,
  ToolAnnotations,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { assertOutsideWorkspace, loadConfig, resolveConfigPath, type PaztportConfig } from "./config.ts";
import { ServerConnection, type CallOutcome } from "./connection.ts";
import { EventLog } from "./events.ts";
import { EvidenceLog } from "./evidence.ts";
import { contentHash, InfluenceStore } from "./influence.ts";
import { loadClientMaterial, type ClientMaterial } from "./keys.ts";
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
 * Makes pi a Paztport harness for the MCP servers named in the config (--paztport-config or
 * PAZTPORT_CONFIG): their tools are registered as `mcp__<server>__<tool>` and every call goes
 * through a {@link ServerConnection}. Without a config the extension does nothing.
 */
export default function paztport(pi: ExtensionAPI): void {
  pi.registerFlag(FLAG, { description: "Path to the Paztport config (JSON); overrides PAZTPORT_CONFIG", type: "string" });

  const influence = new InfluenceStore();
  let runs = new RunState();
  let connections = new Map<string, ServerConnection>();
  /** The evidence file of the current session; a no-op log until a config is loaded. */
  let evidence = new EvidenceLog(undefined);
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

  /** Records one restored tool result as the live path did; any other entry records nothing. */
  function restoreEntry(entry: SessionEntry, ids: Set<string>, mode: PaztportConfig["mode"]): void {
    if (entry.type !== "message") {
      return;
    }
    const m: unknown = entry.message;
    if (!isObject(m) || m.role !== "toolResult" || typeof m.toolName !== "string" || !isMcpTool(m.toolName)) {
      return;
    }
    const d = m.details;
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
      for (const spec of config.servers) {
        if (spec.pin !== undefined) {
          // a missing pin leaves the server unsafe (PIN_MISSING); it is judged by where it would be
          assertOutsideWorkspace(spec.pin, ctx.cwd, `servers.${spec.id}.pin`, { mayBeMissing: true });
        }
      }
      code = "CLIENT_MATERIAL";
      const material = loadClientMaterial(config.clientDir);
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
    const flag = pi.getFlag(FLAG);
    const path = resolveConfigPath(typeof flag === "string" ? flag : undefined, process.env);
    if (path === undefined) {
      return;
    }
    const prepared = prepare(path, ctx);
    const { config, events, material } = prepared;
    evidence = prepared.evidence;
    // before the tools are registered, so every call this session stamps carries the restored influence
    restoreInfluence(ctx.sessionManager, config);
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
      runs.start(event.prompt, ts);
      const run = runs.current();
      if (run !== undefined) {
        evidence.write({ v: 1, type: "run", rid: run.rid, ts, prompt: event.prompt });
      }
    }
  });

  pi.on("tool_result", (event) => {
    if (ownCalls.delete(event.toolCallId)) {
      return; // recorded (or not) by its ServerConnection
    }
    const name = event.toolName;
    if (isMcpTool(name)) {
      influence.recordUntrusted(`builtin:${name}`, hashContent(event.content));
    }
  });

  pi.on("session_shutdown", async () => {
    generation++;
    await closeAll();
  });
}
