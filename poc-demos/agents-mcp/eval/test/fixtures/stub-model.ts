// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A stand-in for the model in a scripted run of the whole demo: an HTTP server that speaks enough of the OpenAI
// chat-completions API for pi's openai-completions provider (pi-ai 1.5.2, api/openai-completions.js) and answers each
// request with the next turn of a fixed script. It is not a model: it reads nothing in the request but the number of
// assistant messages, so what the tools return never changes what it says next.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** One assistant message: the tool calls it makes, or its final answer. */
export type StubTurn = { toolCalls: { id: string; name: string; arguments: Record<string, unknown> }[] } | { text: string };

type Message = { role?: unknown };
type Body = { messages?: unknown; stream?: unknown; model?: unknown };

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });

function fail(res: ServerResponse, status: number, message: string): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: { message, type: "stub_error" } }));
}

/** The OpenAI form of a turn's tool calls, as a message carries them. */
const toolCallsOf = (turn: StubTurn) =>
  "toolCalls" in turn
    ? turn.toolCalls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.arguments) } }))
    : undefined;

/**
 * An OpenAI chat-completions server on 127.0.0.1 (a free port). Each conversation replays `script` from its start:
 * the turn answered is the number of assistant messages in the request. Streams when the request asks for a stream.
 */
export function startStubModel(script: StubTurn[]): Promise<{ baseUrl: string; close(): Promise<void> }> {
  let completions = 0;
  const server = createServer((req, res) => {
    void (async () => {
      if (req.method !== "POST" || !(req.url ?? "").endsWith("/chat/completions")) return fail(res, 404, `no such endpoint: ${req.method} ${req.url}`);
      let body: Body;
      try {
        body = JSON.parse(await readBody(req)) as Body;
      } catch {
        return fail(res, 400, "the request body is not JSON");
      }
      if (!Array.isArray(body.messages)) return fail(res, 400, "the request has no messages");
      const index = (body.messages as Message[]).filter((m) => m?.role === "assistant").length;
      const turn = script[index];
      // a 400 is not retried by pi, so a conversation that outruns the script ends in an error the run records
      if (turn === undefined) return fail(res, 400, `the script has ${script.length} turns and the request asks for turn ${index + 1}`);
      const id = `chatcmpl-stub-${++completions}`;
      const model = typeof body.model === "string" ? body.model : "stub";
      const created = Math.floor(Date.now() / 1000);
      const content = "text" in turn ? turn.text : null;
      const toolCalls = toolCallsOf(turn);
      const finish = toolCalls === undefined ? "stop" : "tool_calls";
      const usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
      if (body.stream !== true) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id, object: "chat.completion", created, model, choices: [{ index: 0, message: { role: "assistant", content, ...(toolCalls ? { tool_calls: toolCalls } : {}) }, finish_reason: finish }], usage }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      const send = (chunk: unknown) => res.write(`data: ${JSON.stringify(chunk)}\n\n`);
      const base = { id, object: "chat.completion.chunk", created, model };
      // a stream's delta carries each tool call whole, with its index in the message
      const deltaCalls = toolCalls?.map((c, index) => ({ index, ...c }));
      send({ ...base, choices: [{ index: 0, delta: { role: "assistant", ...(content !== null ? { content } : {}), ...(deltaCalls ? { tool_calls: deltaCalls } : {}) }, finish_reason: null }] });
      send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: finish }] });
      // the request asks for usage in the stream (stream_options.include_usage): a last chunk with no choices
      send({ ...base, choices: [], usage });
      res.end("data: [DONE]\n\n");
    })().catch((e: unknown) => {
      if (!res.headersSent) fail(res, 500, (e as Error).message);
      else res.destroy();
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${port}/v1`,
        close: () =>
          new Promise<void>((done, failed) => {
            server.close((e) => (e ? failed(e) : done()));
            // pi's client keeps its connection open; the server cannot close until it is gone
            server.closeAllConnections();
          }),
      });
    });
  });
}
