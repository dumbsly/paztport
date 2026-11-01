// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only stdio MCP server with hostile or instrumented results:
//   echo       -> text: JSON {methods, sessions, meta}: methods seen, whether each paztport/session
//                 request carried a clientRoot, and whether this call's params carried _meta
//   surrogate  -> a text holding a lone surrogate (valid JSON, rejected by JCS)
//   infinity   -> a result field 1e400, which parses to Infinity
//   verdict    -> a refusal-shaped result whose verdict token holds arguments.reason
//   untyped.tool -> listed only: an inputSchema without "type" and a name with a "."
//   stringly   -> listed only: an inputSchema whose type is not "object"
// --session-reply malformed answers paztport/session with {}; --session-reply error answers it with a
// JSON-RPC internal error; otherwise it is "method not found".

import { createInterface } from "node:readline";
import { readSessionRequest, writeToken } from "@paztport/core";

const sessionReply = process.argv.includes("--session-reply") ? process.argv[process.argv.indexOf("--session-reply") + 1] : undefined;
const methods: string[] = [];
const sessions: boolean[] = [];
const tools = [
  ...["echo", "surrogate", "infinity", "verdict"].map((name) => ({ name, inputSchema: { type: "object" } as Record<string, unknown> })),
  { name: "untyped.tool", inputSchema: { properties: { x: { type: "string" } } } },
  { name: "stringly", inputSchema: { type: "string" } },
];

const send = (line: string) => process.stdout.write(line + "\n");
const result = (id: unknown, r: unknown) => send(JSON.stringify({ jsonrpc: "2.0", id, result: r }));

createInterface({ input: process.stdin }).on("line", (line) => {
  const m = JSON.parse(line) as { id?: unknown; method?: string; params?: Record<string, any> };
  if (m.id === undefined || m.method === undefined) return;
  methods.push(m.method);
  const p = m.params ?? {};
  switch (m.method) {
    case "initialize":
      return result(m.id, { protocolVersion: p.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "stub", version: "0" } });
    case "tools/list":
      return result(m.id, { tools });
    case "paztport/session":
      sessions.push(readSessionRequest(p.request).clientRoot !== null);
      if (sessionReply === "malformed") return result(m.id, {});
      if (sessionReply === "error") return send(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: "Internal error" } }));
      break;
    case "tools/call":
      switch (p.name) {
        case "echo":
          return result(m.id, { content: [{ type: "text", text: JSON.stringify({ methods, sessions, meta: p._meta !== undefined }) }] });
        case "surrogate":
          return result(m.id, { content: [{ type: "text", text: "bad \ud800 text" }] });
        case "infinity":
          return send(`{"jsonrpc":"2.0","id":${JSON.stringify(m.id)},"result":{"content":[{"type":"text","text":"big"}],"n":1e400}}`);
        case "verdict":
          return result(m.id, {
            content: [{ type: "text", text: "server-chosen refusal text" }],
            isError: true,
            _meta: { "paztport/verdict": writeToken({ reason: p.arguments?.reason ?? null }) },
          });
      }
  }
  send(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } }));
});
