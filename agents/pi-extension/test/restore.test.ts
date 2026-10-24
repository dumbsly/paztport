// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { SessionEntry } from "@earendil-works/pi-coding-agent";
import { SessionChain, walkBranch, type SessionView } from "../src/restore.ts";

const tmp = mkdtempSync(join(tmpdir(), "paztport-restore-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const e = (id: string, parentId: unknown): SessionEntry => ({ type: "message", id, parentId, timestamp: "", message: {} }) as unknown as SessionEntry;
const lookup = (...entries: SessionEntry[]) => (id: string) => entries.find((x) => x.id === id);
const ids = (w: { entries: SessionEntry[] }) => w.entries.map((x) => x.id);

describe("walkBranch", () => {
  it("walksToTheRoot", () => {
    const w = walkBranch(lookup(e("a", null), e("b", "a"), e("c", "b")), "c");
    expect(ids(w)).toEqual(["a", "b", "c"]);
    expect(w.complete).toBe(true);
  });

  it("incompleteOnMissingLoopOrMalformedParent", () => {
    expect(walkBranch(lookup(), "x")).toEqual({ entries: [], complete: false });
    const missing = walkBranch(lookup(e("b", "gone")), "b");
    expect([ids(missing), missing.complete]).toEqual([["b"], false]);
    const loop = walkBranch(lookup(e("a", "b"), e("b", "a")), "a");
    expect([ids(loop), loop.complete]).toEqual([["b", "a"], false]);
    const malformed = walkBranch(lookup(e("a", 7)), "a");
    expect([ids(malformed), malformed.complete]).toEqual([["a"], false]);
  });
});

describe("SessionChain", () => {
  let k = 0;
  /** A session file in dir: a header naming parent, then the entries. */
  function file(dir: string, parent: string | undefined, ...entries: SessionEntry[]): string {
    const path = join(dir, `s${k++}.jsonl`);
    const header = { type: "session", id: `s${k}`, timestamp: "", cwd: "/", ...(parent !== undefined ? { parentSession: parent } : {}) };
    writeFileSync(path, [header, ...entries].map((x) => JSON.stringify(x)).join("\n") + "\n{ not json\n");
    return path;
  }
  const view = (dir: string, parent: string | undefined, ...entries: SessionEntry[]): SessionView =>
    ({
      getBranch: () => entries,
      getEntry: lookup(...entries),
      getHeader: () => (parent !== undefined ? { type: "session", parentSession: parent } : null),
      getSessionDir: () => dir,
    }) as unknown as SessionView;

  it("findsTheBranchInAParentOrGrandparent", () => {
    const dir = join(tmp, "store");
    mkdirSync(dir);
    const grand = file(dir, undefined, e("g", null), e("x", "g"));
    const parent = file(dir, grand, e("g", null), e("p", "g"));
    const chain = new SessionChain(view(dir, parent, e("g", null)));
    expect(chain.branch("p", 0)).toEqual({ entries: [e("g", null), e("p", "g")], complete: true, depth: 1 });
    expect(chain.branch("x", 0)).toMatchObject({ complete: true, depth: 2 });
    // a branch found at depth 1 is not looked up in this session again
    expect(chain.branch("nowhere", 1)).toEqual({ entries: [], complete: false, depth: 1 });
  });

  it("readsOnlyJsonlInsideTheSessionDirOnce", () => {
    const dir = join(tmp, "store2");
    const other = join(tmp, "other");
    mkdirSync(dir);
    mkdirSync(other);
    const outside = file(other, undefined, e("o", null));
    expect(new SessionChain(view(dir, outside)).branch("o", 0).complete).toBe(false);
    const txt = join(dir, "notes.txt");
    writeFileSync(txt, JSON.stringify(e("t", null)) + "\n");
    expect(new SessionChain(view(dir, txt)).branch("t", 0).complete).toBe(false);
    // in-memory sessions have no directory, so no parents
    expect(new SessionChain(view("", outside)).branch("o", 0).complete).toBe(false);
    // parents that name each other are each read once
    const a = join(dir, "a.jsonl");
    const b = file(dir, a, e("b", null));
    writeFileSync(a, JSON.stringify({ type: "session", parentSession: b }) + "\n");
    expect(new SessionChain(view(dir, a)).branch("nowhere", 0).complete).toBe(false);
    expect(new SessionChain(view(dir, a)).branch("b", 0)).toMatchObject({ complete: true, depth: 2 });
  });
});
