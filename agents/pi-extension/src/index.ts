// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import type { Tool } from "@earendil-works/pi-mcp";
import type {
  AgentToolResult,
  ExtensionAPI,
  ExtensionContext,
  ToolAnnotations,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { assertOutsideWorkspace, loadConfig, resolveConfigPath, type PaztportConfig } from "./config.ts";
import { ServerConnection, type CallOutcome } from "./connection.ts";
import { EventLog } from "./events.ts";
import { contentHash, InfluenceStore } from "./influence.ts";
import { loadClientMaterial, type ClientMaterial } from "./keys.ts";
import { RunState } from "./runs.ts";

const FLAG = "paztport-config";
/** Provider tool names are limited to 64 characters. */
const MAX_TOOL_NAME = 64;
/** pi's built-in MCP resource tools; like its `mcp__` tools they return MCP server content. */
const BUILTIN_MCP_RESOURCE_TOOLS = new Set(["list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource"]);
const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;

type Details = CallOutcome["details"] | { server: string; influence: Record<string, number> };
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

/** The remote inputSchema, with `type` defaulting to "object" (pi requires an object schema). */
function parametersOf(tool: Tool): Parameters {
  const schema = isObject(tool.inputSchema) ? tool.inputSchema : {};
  return { ...schema, type: schema.type ?? "object" } as unknown as Parameters;
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
 * Hash of a result that reached the model through pi's built-in MCP. Content JCS rejects (a lone
 * surrogate) is hashed through its JSON text instead, so it is still recorded.
 */
function builtinHash(content: unknown): string {
  try {
    return contentHash({ content });
  } catch {
    return contentHash({ content: [{ type: "text", text: JSON.stringify(content) }] });
  }
}

const text = (t: string) => [{ type: "text" as const, text: t }];

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
  /** Every tool name this extension registered, to its server id and remote tool name. */
  const registered = new Map<string, { server: string; tool: string }>();
  /** Bumped by session_start and session_shutdown, so a superseded start drops its connections. */
  let generation = 0;

  async function closeAll(): Promise<void> {
    const open = [...connections.values()];
    connections = new Map();
    await Promise.all(open.map((c) => c.close()));
  }

  async function execute(name: string, params: unknown, toolCallId: string): Promise<AgentToolResult<Details>> {
    const target = registered.get(name);
    const server = target?.server ?? name;
    const conn = target !== undefined ? connections.get(target.server) : undefined;
    if (target === undefined || conn === undefined) {
      return { content: text(`MCP server "${server}" is not connected`), details: { server, influence: influence.summary() }, isError: true };
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
    registered.set(name, { server: serverId, tool: tool.name });
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
  }

  /** Loads the config, guards the workspace and loads the keys; throws (after any refused_start) if any fails. */
  function prepare(path: string, ctx: ExtensionContext): { config: PaztportConfig; events: EventLog; material: ClientMaterial } {
    let events: EventLog | undefined;
    let code = "CONFIG";
    try {
      const config = loadConfig(path);
      code = "EVENTS_LOG";
      events = new EventLog(config.eventsLog);
      code = "WORKSPACE_GUARD";
      assertOutsideWorkspace(config.clientDir, ctx.cwd);
      code = "CLIENT_MATERIAL";
      const material = loadClientMaterial(config.clientDir);
      return { config, events, material };
    } catch (e) {
      events?.emit({ type: "refused_start", code });
      throw new Error(`Paztport refused to start: ${(e as Error).message}`);
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    const gen = ++generation;
    await closeAll();
    influence.reset();
    runs = new RunState();
    const flag = pi.getFlag(FLAG);
    const path = resolveConfigPath(typeof flag === "string" ? flag : undefined, process.env);
    if (path === undefined) {
      return;
    }
    const { config, events, material } = prepare(path, ctx);
    const fresh = config.servers.map((spec) => new ServerConnection(spec, config.mode, material, influence, runs, events));
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
        register(spec.id, tool);
      }
    });
    if (failed.length > 0) {
      throw new Error(`Paztport: ${failed.join("; ")}`);
    }
  });

  pi.on("before_agent_start", (event) => {
    if (event.messageType === "user") {
      runs.start(event.prompt, Date.now());
    }
  });

  pi.on("tool_result", (event) => {
    const name = event.toolName;
    if ((name.startsWith("mcp__") || BUILTIN_MCP_RESOURCE_TOOLS.has(name)) && !registered.has(name)) {
      influence.recordUntrusted(`builtin:${name}`, builtinHash(event.content));
    }
  });

  pi.on("session_shutdown", async () => {
    generation++;
    await closeAll();
  });
}
