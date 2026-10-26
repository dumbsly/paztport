// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";

/**
 * Optional JSONL events log for the demo UI. Callers emit only types, tool and server names, reason
 * codes, classes, rids and callIds: never content, arguments, keys, signatures, session ids or hashes.
 */
export class EventLog {
  private readonly path: string | undefined;

  /** Without a path every emit is a no-op. An unwritable path throws here, not on the first emit. */
  constructor(path: string | undefined) {
    this.path = path;
    if (path !== undefined) {
      appendFileSync(path, "");
    }
  }

  /** Appends one line with `ts` added. A failed write is dropped so tool calls never fail on logging. */
  emit(e: Record<string, unknown>): void {
    if (this.path === undefined) {
      return;
    }
    try {
      appendFileSync(this.path, JSON.stringify({ ts: Date.now(), ...e }) + "\n");
    } catch {
      // logging is best effort
    }
  }
}
