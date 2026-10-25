// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseLocalRules } from "@paztport/path-attest";
import { canonical, piRewrites, resolveFileTool, resolvePathArg, type PathContext } from "../src/local/paths.ts";

const rules = parseLocalRules({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
    { path: "notes", access: ["read", "write"], destination: "private" },
  ],
  programs: ["cat"],
});

let base: string;
let ws: string;
let outside: string;
let shared: string;
let ctx: PathContext;
let caseInsensitive = false;

beforeAll(() => {
  base = realpathSync.native(mkdtempSync(join(tmpdir(), "pz-paths-")));
  ws = join(base, "ws");
  outside = join(base, "outside");
  shared = join(base, "shared");
  for (const d of [ws, outside, shared, join(ws, "website"), join(ws, "notes"), join(ws, "secrets")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(ws, "website", "README.md"), "x");
  writeFileSync(join(outside, "f"), "x");
  symlinkSync(outside, join(ws, "website", "link"));
  symlinkSync(join(base, "nowhere"), join(ws, "website", "dangling"));
  symlinkSync(shared, join(ws, "sharedlink"));
  caseInsensitive = existsSync(join(ws, "WEBSITE", "README.md"));
  ctx = { cwd: ws, workspace: ws, rules, refused: [canonical(join(ws, "secrets"))] };
});
afterAll(() => rmSync(base, { recursive: true, force: true }));

describe("piRewrites", () => {
  it("flagsWhatPisNormalizePathWouldChange", () => {
    for (const p of ["@a", "a b", "a b", "a b", "a b", "a　b", "a﻿b", "~", "~/x", "file:///etc/passwd"]) {
      expect(piRewrites(p), JSON.stringify(p)).toBe(true);
    }
  });
  it("leavesPlainPathsAlone", () => {
    for (const p of ["a b", "a/~/b", "~user", "./x", "/abs/x", "a@b", "file:/x"]) expect(piRewrites(p), p).toBe(false);
  });
});

describe("canonical", () => {
  it("resolvesExistingAncestorAndKeepsRemainder", () => {
    expect(canonical(join(ws, "website", "new", "deep.md"))).toBe(join(ws, "website", "new", "deep.md"));
    expect(canonical(join(ws, "website", "link", "zzz"))).toBe(join(outside, "zzz"));
  });
  it("throwsForADanglingSymlink", () => {
    expect(() => canonical(join(ws, "website", "dangling"))).toThrow();
  });
});

describe("resolvePathArg", () => {
  const r = (arg: string, need: "read" | "write" = "read", c = ctx) => resolvePathArg(arg, need, c);

  it("relativeAndRootPaths", () => {
    expect(r("website/README.md")).toEqual({ need: "read", at: "website/README.md" });
    expect(r(".")).toEqual({ need: "read", at: "." });
    expect(r(ws)).toEqual({ need: "read", at: "." });
    expect(r("website/")).toEqual({ need: "read", at: "website" });
    expect(r(join(ws, "notes", "a.md"), "write")).toEqual({ need: "write", at: "notes/a.md" });
  });
  it("notYetExistingFile", () => {
    expect(r("website/new.md", "write")).toEqual({ need: "write", at: "website/new.md" });
  });
  it("relativeToCwdNotWorkspace", () => {
    const c = { ...ctx, cwd: join(ws, "website") };
    expect(r("README.md", "read", c).at).toBe("website/README.md");
    expect(r("../notes/x", "read", c).at).toBe("notes/x");
  });
  it("outside", () => {
    expect(r("../x").at).toBe("outside");
    expect(r(outside).at).toBe("outside");
    expect(r("/etc/passwd").at).toBe("outside");
    expect(r("../ws-evil/x").at).toBe("outside");
  });
  it("pathThroughSymlinkIsJudgedByTarget", () => {
    expect(r("website/link").at).toBe("outside");
    expect(r("website/link/f").at).toBe("outside");
    expect(r("website/link/new", "write").at).toBe("outside");
  });
  it("danglingSymlinkIsUncheckable", () => {
    expect(r("website/dangling", "write").at).toBe("uncheckable");
  });
  it("piRewritesAndNulAreUncheckable", () => {
    expect(r("@website/a").at).toBe("uncheckable");
    expect(r("~/x").at).toBe("uncheckable");
    expect(r("file:///etc/passwd").at).toBe("uncheckable");
    expect(r("website/a\0b").at).toBe("uncheckable");
  });
  it("refusedWinsOverWorkspace", () => {
    expect(r("secrets/key").at).toBe("refused");
    expect(r("secrets").at).toBe("refused");
    expect(r("secretsx").at).toBe("secretsx");
  });
  it("caseChangedPathResolvesToCanonicalCase", () => {
    if (!caseInsensitive) return;
    expect(r("Website/README.md").at).toBe("website/README.md");
  });
  it("caseChangedPathIntoRefusedIsRefused", () => {
    if (!caseInsensitive) return;
    expect(r("SECRETS/key").at).toBe("refused");
    expect(r("Secrets").at).toBe("refused");
  });
  it("refusedEntriesAreCanonicalisedLikeThePath", () => {
    const c = { ...ctx, refused: [join(ws, "sharedlink")] };
    expect(r("sharedlink/a", "read", c).at).toBe("refused");
    expect(r(join(shared, "a"), "read", c).at).toBe("refused");
  });
  it("absoluteFolderRulesGiveAbsoluteAt", () => {
    const abs = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }, { path: join(ws, "sharedlink"), access: ["read"] }], programs: [] });
    const c = { ...ctx, rules: abs };
    expect(r(join(shared, "a.txt"), "read", c).at).toBe(join(ws, "sharedlink", "a.txt"));
    expect(r(join(outside, "f"), "read", c).at).toBe("outside");
    const abs2 = parseLocalRules({ v: 1, folders: [{ path: shared + "/", access: ["read"] }], programs: [] });
    expect(r(join(shared, "a.txt"), "read", { ...ctx, rules: abs2 }).at).toBe(join(shared, "a.txt"));
    expect(r(shared, "read", { ...ctx, rules: abs2 }).at).toBe(shared);
  });
});

describe("resolveFileTool", () => {
  it("lsWithoutPathChecksCwd", () => {
    expect(resolveFileTool("ls", {}, ctx)).toEqual({ paths: [{ need: "read", at: "." }], programs: [], parse: "ok", readOnly: true });
  });
  it("needsPerTool", () => {
    for (const t of ["read", "grep", "find", "ls"] as const) {
      const x = resolveFileTool(t, { path: "website/README.md" }, ctx);
      expect(x.paths).toEqual([{ need: "read", at: "website/README.md" }]);
      expect(x.readOnly).toBe(true);
    }
    for (const t of ["write", "edit"] as const) {
      const x = resolveFileTool(t, { path: "notes/a.md" }, ctx);
      expect(x.paths).toEqual([{ need: "write", at: "notes/a.md" }]);
      expect(x.readOnly).toBe(false);
    }
  });
  it("globOrPatternThatEscapesIsUncheckable", () => {
    expect(resolveFileTool("grep", { path: "website", glob: "../*" }, ctx).paths[0]?.at).toBe("uncheckable");
    expect(resolveFileTool("grep", { path: "website", glob: "/etc/*" }, ctx).paths[0]?.at).toBe("uncheckable");
    expect(resolveFileTool("find", { path: "website", pattern: "a/../b" }, ctx).paths[0]?.at).toBe("uncheckable");
    expect(resolveFileTool("grep", { path: "website", glob: "*.md" }, ctx).paths[0]?.at).toBe("website");
    expect(resolveFileTool("find", { path: "website", pattern: "*.md" }, ctx).paths[0]?.at).toBe("website");
  });
  it("aNonStringPathIsUncheckable", () => {
    expect(resolveFileTool("read", { path: 5 }, ctx).paths[0]?.at).toBe("uncheckable");
  });
});
