// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, realpathSync, statSync } from "node:fs";
import { sep } from "node:path";
import type { ExtensionContext, SessionEntry } from "@earendil-works/pi-coding-agent";

/** What restoring influence reads of pi's session (all on pi 1.5.2's ReadonlySessionManager). */
export type SessionView = Pick<ExtensionContext["sessionManager"], "getBranch" | "getEntry" | "getHeader" | "getSessionDir">;

type Lookup = (id: string) => SessionEntry | undefined;

/** A branch walked back from an entry, root first; complete only if it reached a root. */
export type Walk = { entries: SessionEntry[]; complete: boolean };

/** How many parentSession links are followed. */
const MAX_PARENTS = 8;
/** The largest parent session file read. */
const MAX_PARENT_BYTES = 64 * 1024 * 1024;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The entries from `id` back to the root, root first. Incomplete when `id` or an ancestor is
 * missing, a parentId is malformed, or the parent chain loops (pi's own getBranch has no cycle guard).
 */
export function walkBranch(get: Lookup, id: string): Walk {
  const entries: SessionEntry[] = [];
  const visited = new Set<string>();
  let next: unknown = id;
  while (next !== null) {
    if (typeof next !== "string" || visited.has(next)) {
      return { entries: entries.reverse(), complete: false };
    }
    visited.add(next);
    const e = get(next);
    if (!isObject(e)) {
      return { entries: entries.reverse(), complete: false };
    }
    entries.push(e);
    next = e.parentId;
  }
  return { entries: entries.reverse(), complete: true };
}

function parentOf(header: unknown): string | undefined {
  return isObject(header) && typeof header.parentSession === "string" ? header.parentSession : undefined;
}

/**
 * Entry lookups for a session, then for the sessions it was forked or cloned from, nearest first.
 * pi's /fork and /clone write only the current path to the new session file and name the old file
 * in the header's parentSession, so a branch summarised there is found in the parent. A parent is
 * read only if it is a regular .jsonl file under this session's directory (pi's session store) of at
 * most maxBytes, at most MAX_PARENTS deep, each file once; it is read and parsed as JSONL, never
 * written. Anything else (a FIFO, which would block the read, a directory, an oversize file) is
 * unreadable, so its summaries stay unresolved. Parents load on first use.
 */
export class SessionChain {
  private readonly lookups: Lookup[];
  private readonly dir: string | undefined;
  private readonly files = new Set<string>();
  private parent: string | undefined;
  private readonly maxBytes: number;

  constructor(session: SessionView, opts: { maxBytes?: number } = {}) {
    this.maxBytes = opts.maxBytes ?? MAX_PARENT_BYTES;
    this.lookups = [(id) => session.getEntry(id)];
    let dir: string | undefined;
    try {
      dir = realpathSync(session.getSessionDir()); // "" for an in-memory session: no parents
    } catch {
      dir = undefined;
    }
    this.dir = dir;
    this.parent = parentOf(session.getHeader());
  }

  /**
   * The branch ending at `fromId`, looked up in the session at `depth` (0 is this session) and then
   * in its parents. Returns the first complete walk with the depth it was found at; failing that,
   * the first partial one (complete: false), so what does resolve is still counted.
   */
  branch(fromId: unknown, depth: number): Walk & { depth: number } {
    let partial = { entries: [] as SessionEntry[], complete: false, depth };
    if (typeof fromId !== "string") {
      return partial;
    }
    for (let d = depth; this.at(d) !== undefined; d++) {
      const walk = walkBranch(this.at(d)!, fromId);
      if (walk.complete) {
        return { ...walk, depth: d };
      }
      if (partial.entries.length === 0 && walk.entries.length > 0) {
        partial = { ...walk, depth: d };
      }
    }
    return partial;
  }

  private at(depth: number): Lookup | undefined {
    while (this.lookups.length <= depth && this.loadParent()) {
      // loads one parent per pass
    }
    return this.lookups[depth];
  }

  private loadParent(): boolean {
    const file = this.parent;
    this.parent = undefined;
    if (file === undefined || this.dir === undefined || this.lookups.length > MAX_PARENTS) {
      return false;
    }
    let text: string;
    try {
      const real = realpathSync(file);
      if (!real.endsWith(".jsonl") || !real.startsWith(this.dir + sep) || this.files.has(real)) {
        return false;
      }
      this.files.add(real);
      const st = statSync(real);
      if (!st.isFile() || st.size > this.maxBytes) {
        return false;
      }
      text = readFileSync(real, "utf8");
    } catch {
      return false;
    }
    const byId = new Map<string, SessionEntry>();
    let header: unknown;
    for (const line of text.split("\n")) {
      let v: unknown;
      try {
        v = JSON.parse(line);
      } catch {
        continue; // blank or malformed, as pi skips them
      }
      if (!isObject(v)) {
        continue;
      }
      if (v.type === "session") {
        header ??= v;
      } else if (typeof v.id === "string") {
        byId.set(v.id, v as unknown as SessionEntry);
      }
    }
    this.lookups.push((id) => byId.get(id));
    this.parent = parentOf(header);
    return true;
  }
}
