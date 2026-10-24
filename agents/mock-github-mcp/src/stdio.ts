// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createInterface } from "node:readline";

/**
 * Serve one JSON-RPC message per line. Lines are handled concurrently; each response is
 * written as exactly one line. Resolves once input has ended and all handlers have settled.
 */
export function serveStdio(
  handler: { handle(m: unknown): Promise<object | undefined> },
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream,
): Promise<void> {
  const pending = new Set<Promise<void>>();
  const send = (msg: object): void => {
    output.write(JSON.stringify(msg) + "\n");
  };

  async function handleLine(line: string): Promise<void> {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    try {
      const res = await handler.handle(msg);
      if (res !== undefined) send(res);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } });
    }
  }

  return new Promise((resolve) => {
    const rl = createInterface({ input, crlfDelay: Infinity });
    rl.on("line", (line) => {
      if (line.trim() === "") return;
      const p = handleLine(line).finally(() => pending.delete(p));
      pending.add(p);
    });
    rl.on("close", () => {
      void Promise.all(pending).then(() => resolve());
    });
  });
}
