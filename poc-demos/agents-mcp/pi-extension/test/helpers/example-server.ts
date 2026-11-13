// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only stdio MCP server that attests each response with a last block requiring `example` as well as `influence`,
// so a client that acts on influence alone withholds the result (check 9c). It runs as the demo's GitHub server
// (`node example-server.ts <demo>/server`): the same keys, route and server id, with one tool, list_issues, whose
// result carries one `public` label. The handshake and the call check are the SDK's McpServerSession; the response
// chain is signed here as McpServerSession.attest signs it, but for the tools hop's block.

import { createInterface } from "node:readline";
import {
  bindResponse, bindResult, commitBlock, extensionSettings, INFLUENCE, influenceBlock, newContentId, signStamp,
  writeToken, type JsonValue, type ResponseAttestation,
} from "@paztport/core";
import { bindMcpCall, McpServerSession, META_ATTESTATION, refusedToolResult } from "@paztport/mcp";
import { loadServerConfig } from "../../../mock-github-mcp/src/paztport.ts";

const policy = loadServerConfig(process.argv[2]!);
const rules = { disabledWhenUnsafe: [] };
const server = new McpServerSession(policy, rules, extensionSettings([INFLUENCE]), Date.now, () => {});
const tools = [{ name: "list_issues", inputSchema: { type: "object" } }];
const serverInfo = { name: "example", version: "0" };
const capabilities = { tools: {} };

const send = (m: object) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n");

/** The result, attested by the entry then the tools hop, whose block holds a `public` label and requires `example`. */
function attested(params: Record<string, any>): object {
  const check = server.checkCall(params);
  if (check.reason !== "OK") return refusedToolResult(check.reason);
  const result = { content: [{ type: "text", text: "Issue 1: Typo in README" }] };
  const [entry, hop] = policy.hops;
  const blocks = [influenceBlock([]), influenceBlock([{ cls: "public", cid: newContentId() }], ["example", INFLUENCE])];
  const resultHash = bindResult(result);
  const base = { rid: check.rid, ts: Date.now(), inst: policy.inst, sess: check.session.sess };
  const took = bindMcpCall(params.name, check.callId, params.arguments ?? {});
  const s0 = signStamp(
    { ...base, svc: entry, rcv: hop, bind: took, ext: commitBlock(blocks[0]!), prev: "" },
    policy.signingKeys[entry]!,
  );
  const answered = bindResponse(resultHash, check.callId);
  const s1 = signStamp(
    { ...base, svc: hop, rcv: check.caller, bind: answered, ext: commitBlock(blocks[1]!), prev: s0.sig },
    policy.signingKeys[hop]!,
  );
  const attestation: ResponseAttestation = { blocks, chain: [s0, s1], proof: policy.routeProof, resultHash };
  return { ...result, _meta: { [META_ATTESTATION]: writeToken(attestation as unknown as JsonValue) } };
}

createInterface({ input: process.stdin }).on("line", (line) => {
  const m = JSON.parse(line) as { id?: unknown; method?: string; params?: Record<string, any> };
  if (m.id === undefined || m.method === undefined) return;
  const p = m.params ?? {};
  switch (m.method) {
    case "initialize":
      return send({ id: m.id, result: { protocolVersion: p.protocolVersion, capabilities, serverInfo } });
    case "tools/list":
      return send({ id: m.id, result: { tools } });
    case "paztport/session":
      return send({ id: m.id, result: server.openSession(p) });
    case "tools/call":
      if (p.name === "list_issues") return send({ id: m.id, result: attested(p) });
  }
  send({ id: m.id, error: { code: -32601, message: "Method not found" } });
});
