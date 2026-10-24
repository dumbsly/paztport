// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createMcpHandler } from "../src/mcp.ts";
import { serveStdio } from "../src/stdio.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function run(lines: string[], delays: Record<string, number> = {}) {
  const handler = createMcpHandler({
    serverInfo: { name: "t", version: "1" },
    tools: [{ name: "slow", description: "", inputSchema: {} }],
    callTool: async (_n, p) => {
      const id = (p.arguments as { id: string }).id;
      await sleep(delays[id] ?? 0);
      return { content: [{ type: "text", text: id }] };
    },
  });
  const input = new PassThrough();
  const output = new PassThrough();
  let out = "";
  output.on("data", (d) => (out += d));
  const done = serveStdio(handler, input, output).then(() => out);
  for (const l of lines) input.write(l + "\n");
  input.end();
  return done;
}

const parse = (out: string) => out.split("\n").filter(Boolean).map((l) => JSON.parse(l));

describe("stdio", () => {
  it("oneResponsePerLine", async () => {
    const out = await run([
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    ]);
    expect(out.endsWith("\n")).toBe(true);
    const msgs = parse(out);
    expect(msgs.map((m) => m.id).sort()).toEqual([1, 2]);
  });

  it("badLineDoesNotKillServer", async () => {
    const msgs = parse(await run(["not json {", JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" })]));
    expect(msgs[0].id).toBeNull();
    expect(msgs[0].error.code).toBe(-32700);
    expect(msgs.find((m) => m.id === 7).result).toEqual({});
  });

  it("interleavedRequestsAnsweredById", async () => {
    const call = (id: number, tid: string) =>
      JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "slow", arguments: { id: tid } } });
    const msgs = parse(await run([call(1, "a"), call(2, "b")], { a: 60, b: 5 }));
    expect(msgs.map((m) => m.id)).toEqual([2, 1]);
    expect(msgs[0].result.content[0].text).toBe("b");
    expect(msgs[1].result.content[0].text).toBe("a");
  });

  it("finalLineWithoutNewlineIsHandled", async () => {
    const handler = createMcpHandler({ serverInfo: { name: "t", version: "1" }, tools: [], callTool: async () => ({ content: [] }) });
    const input = new PassThrough();
    const output = new PassThrough();
    let out = "";
    output.on("data", (d) => (out += d));
    const done = serveStdio(handler, input, output);
    input.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }));
    await done;
    expect(parse(out)).toHaveLength(1);
  });
});
