// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { createMcpHandler } from "../src/mcp.ts";
import type { McpHandlerOptions } from "../src/mcp.ts";

const tools = [{ name: "echo", description: "echo", inputSchema: { type: "object" } }];

function make(over: Partial<McpHandlerOptions> = {}) {
  return createMcpHandler({
    serverInfo: { name: "t", version: "1" },
    tools,
    callTool: async (_n, p) => ({ content: [{ type: "text", text: JSON.stringify(p) }] }),
    ...over,
  });
}

describe("mcp core", () => {
  it("initializeEchoesSupportedVersion", async () => {
    for (const v of ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]) {
      const r: any = await make().handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: v } });
      expect(r.id).toBe(1);
      expect(r.result.protocolVersion).toBe(v);
      expect(r.result.capabilities).toEqual({ tools: {} });
      expect(r.result.serverInfo).toEqual({ name: "t", version: "1" });
    }
  });

  it("initializeFallsBackTo20250618", async () => {
    const r: any = await make().handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "1999-01-01" } });
    expect(r.result.protocolVersion).toBe("2025-06-18");
    const r2: any = await make().handle({ jsonrpc: "2.0", id: 2, method: "initialize" });
    expect(r2.result.protocolVersion).toBe("2025-06-18");
  });

  it("pingReturnsEmptyObject", async () => {
    expect(await make().handle({ jsonrpc: "2.0", id: "a", method: "ping" })).toEqual({ jsonrpc: "2.0", id: "a", result: {} });
  });

  it("toolsListReturnsSpecs", async () => {
    const r: any = await make().handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(r.result).toEqual({ tools });
  });

  it("toolsCallRoutesWholeParams", async () => {
    const params = { name: "echo", arguments: { a: 1 }, _meta: { k: "v" } };
    const r: any = await make().handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params });
    expect(JSON.parse(r.result.content[0].text)).toEqual(params);
  });

  it("unknownToolIsInvalidParams", async () => {
    const r: any = await make().handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "nope" } });
    expect(r.error.code).toBe(-32602);
    expect(r.id).toBe(4);
  });

  it("unknownMethodIsMethodNotFound", async () => {
    const r: any = await make().handle({ jsonrpc: "2.0", id: 5, method: "nope/x" });
    expect(r.error.code).toBe(-32601);
  });

  it("extraMethodsAreRouted", async () => {
    const h = make({ methods: { "x/y": async (p) => ({ got: p }) } });
    const r: any = await h.handle({ jsonrpc: "2.0", id: 6, method: "x/y", params: { q: 1 } });
    expect(r.result).toEqual({ got: { q: 1 } });
  });

  it("invalidRequestIsMinus32600", async () => {
    const h = make();
    for (const m of [null, 5, [], { jsonrpc: "1.0", id: 1, method: "ping" }, { jsonrpc: "2.0", id: 1 }, { jsonrpc: "2.0", id: {}, method: "ping" }]) {
      const r: any = await h.handle(m);
      expect(r.error.code).toBe(-32600);
    }
  });

  it("notificationGetsNoResponse", async () => {
    const h = make();
    expect(await h.handle({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeUndefined();
    expect(await h.handle({ jsonrpc: "2.0", method: "nope" })).toBeUndefined();
  });

  it("throwingHandlerIsInternalErrorWithoutStack", async () => {
    const h = make({
      callTool: async () => { throw new Error("boom at /secret/path"); },
      methods: { "x/y": async () => { throw new Error("bad"); } },
    });
    for (const msg of [
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo" } },
      { jsonrpc: "2.0", id: 2, method: "x/y" },
    ]) {
      const r: any = await h.handle(msg);
      expect(r.error.code).toBe(-32603);
      expect(JSON.stringify(r)).not.toMatch(/boom|secret|\bat \S+:\d+|stack/);
    }
  });
});
