// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createInterface } from "node:readline";

/** Thrown by write() when a message cannot be serialized or written, so send() can fall back. */
class SerializeError extends Error {}

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
  // A destroyed or failing output must not crash the process or reject the drain.
  output.on("error", () => {});
  const write = (msg: object): void => {
    try {
      output.write(JSON.stringify(msg) + "\n");
    } catch {
      // rethrown as SerializeError; send() falls back to an error reply
      throw new SerializeError();
    }
  };
  const send = (msg: object, id: unknown): void => {
    try {
      write(msg);
    } catch {
      try {
        write({ jsonrpc: "2.0", id, error: { code: -32603, message: "Internal error" } });
      } catch {
        // output unusable; drop
      }
    }
  };

  async function handleLine(line: string): Promise<void> {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, null);
      return;
    }
    const rid = (msg as { id?: unknown } | null)?.id;
    const id = typeof rid === "string" || typeof rid === "number" ? rid : null;
    let res: object | undefined;
    try {
      res = await handler.handle(msg);
    } catch {
      send({ jsonrpc: "2.0", id, error: { code: -32603, message: "Internal error" } }, id);
      return;
    }
    if (res !== undefined) send(res, id);
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
