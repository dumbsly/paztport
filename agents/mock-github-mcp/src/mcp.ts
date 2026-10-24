// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

export type CallToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: unknown;
  _meta?: Record<string, unknown>;
};

export type McpToolSpec = {
  name: string;
  description: string;
  inputSchema: object;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
};

export type McpHandlerOptions = {
  serverInfo: { name: string; version: string };
  tools: McpToolSpec[];
  /** `params` is the whole tools/call params object, including `arguments` and `_meta`. */
  callTool(name: string, params: Record<string, unknown>): Promise<CallToolResult>;
  methods?: Record<string, (params: unknown) => Promise<unknown>>;
};

const SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const FALLBACK_VERSION = "2025-06-18";

type Id = string | number | null;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function fail(id: Id, code: number, message: string): object {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export function createMcpHandler(opts: McpHandlerOptions): { handle(message: unknown): Promise<object | undefined> } {
  const toolNames = new Set(opts.tools.map((t) => t.name));

  async function dispatch(method: string, params: unknown): Promise<{ result: unknown } | { code: number; message: string }> {
    try {
      switch (method) {
        case "initialize": {
          const asked = isObject(params) ? params.protocolVersion : undefined;
          const protocolVersion =
            typeof asked === "string" && SUPPORTED_VERSIONS.includes(asked) ? asked : FALLBACK_VERSION;
          return { result: { protocolVersion, capabilities: { tools: {} }, serverInfo: opts.serverInfo } };
        }
        case "ping":
          return { result: {} };
        case "tools/list":
          return { result: { tools: opts.tools } };
        case "tools/call": {
          if (!isObject(params) || typeof params.name !== "string" || !toolNames.has(params.name)) {
            return { code: -32602, message: "Invalid params: unknown tool" };
          }
          const res: unknown = await opts.callTool(params.name, params);
          if (!isObject(res)) return { code: -32603, message: "Internal error" };
          return { result: res };
        }
      }
      const extra = opts.methods && Object.hasOwn(opts.methods, method) ? opts.methods[method] : undefined;
      if (extra) return { result: (await extra(params)) ?? {} };
      return { code: -32601, message: "Method not found" };
    } catch {
      return { code: -32603, message: "Internal error" };
    }
  }

  return {
    async handle(message) {
      if (!isObject(message)) return fail(null, -32600, "Invalid Request");
      const hasId = "id" in message;
      const rawId = message.id;
      const idOk = typeof rawId === "string" || (typeof rawId === "number" && Number.isFinite(rawId)) || rawId === null;
      if (hasId && !idOk) return fail(null, -32600, "Invalid Request");
      if (message.jsonrpc !== "2.0" || typeof message.method !== "string") {
        return fail(hasId ? (rawId as Id) : null, -32600, "Invalid Request");
      }
      const out = await dispatch(message.method, message.params);
      if (!hasId) return undefined;
      const id = rawId as Id;
      return "result" in out ? { jsonrpc: "2.0", id, result: out.result } : fail(id, out.code, out.message);
    },
  };
}
