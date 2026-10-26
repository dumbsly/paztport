// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decideLocal, folderRuleFor, parseLocalRules, readLabels } from "@paztport/core";
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
// Detected once at module load, on the temp volume, so skipIf can see it.
const caseInsensitive = (() => {
  const d = mkdtempSync(join(tmpdir(), "pz-case-"));
  try {
    writeFileSync(join(d, "aB"), "x");
    return existsSync(join(d, "Ab"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
})();

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
  mkdirSync(join(ws, "docs"));
  mkdirSync(join(base, "out"));
  symlinkSync(join(base, "out"), join(ws, "notes2"));
  symlinkSync(base, join(ws, "up"));
  mkdirSync(join(ws, "s"));
  mkdirSync(join(ws, "c", "b"), { recursive: true });
  symlinkSync(join(ws, "c"), join(ws, "a"));
  mkdirSync(join(ws, "secrets", "keys"));
  mkdirSync(join(ws, "tree", "deep"), { recursive: true });
  mkdirSync(join(ws, "tree", "vault"), { recursive: true });
  mkdirSync(join(ws, "tree", "noread"), { recursive: true });
  writeFileSync(join(outside, "f2"), "x");
  symlinkSync(outside, join(ws, "docs", "r\u202FAM.d"));
  symlinkSync(outside, join(ws, "docs", "it\u2019s"));
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
  it.skipIf(!caseInsensitive)("caseChangedPathResolvesToCanonicalCase", () => {
    expect(r("Website/README.md").at).toBe("website/README.md");
  });
  it.skipIf(!caseInsensitive)("caseChangedPathIntoRefusedIsRefused", () => {
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
    expect(resolveFileTool("ls", {}, { ...ctx, refused: [] })).toEqual({ paths: [{ need: "read", at: "." }, { need: "read", at: "website" }, { need: "read", at: "notes" }], programs: [], parse: "ok", readOnly: true });
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

describe("resolveFileTool read variants", () => {
  it("aPlantedNarrowNoBreakSpaceSymlinkMakesTheReadUncheckable", () => {
    expect(resolveFileTool("read", { path: "docs/r AM.d/f" }, ctx).paths[0]?.at).toBe("uncheckable");
  });
  it("aPlantedCurlyQuoteSymlinkMakesTheReadUncheckable", () => {
    expect(resolveFileTool("read", { path: "docs/it's/f" }, ctx).paths[0]?.at).toBe("uncheckable");
  });
  it("aMissingFileWithNoVariantIsJudgedNormally", () => {
    expect(resolveFileTool("read", { path: "docs/none AM.d/f" }, ctx).paths[0]?.at).toBe("docs/none AM.d/f");
  });
  it("writeIsNotAffectedByReadVariants", () => {
    expect(resolveFileTool("write", { path: "docs/r AM.d/f" }, ctx).paths[0]?.at).toBe("docs/r AM.d/f");
  });
});

describe("searches walk everything below the root", () => {
  const nested = () => {
    const rs = parseLocalRules({
      v: 1,
      folders: [
        { path: ".", access: ["read"] },
        { path: "tree/vault", access: ["read"], label: "private" },
        { path: "tree/noread", access: ["write"], destination: "private" },
      ],
      programs: [],
    });
    return { ...ctx, rules: rs, refused: [] };
  };
  it("aNestedRefusedEntryRefusesTheWholeSearch", () => {
    const c = { ...ctx, refused: [canonical(join(ws, "secrets", "keys"))] };
    for (const t of ["grep", "find", "ls"] as const) {
      expect(resolveFileTool(t, { path: "." }, c).paths[0]?.at).toBe("refused");
      expect(resolveFileTool(t, { path: "secrets" }, c).paths[0]?.at).toBe("refused");
    }
    expect(resolveFileTool("grep", { path: "website" }, c).paths[0]?.at).toBe("website");
    expect(resolveFileTool("read", { path: "." }, c).paths[0]?.at).toBe(".");
  });
  it("nestedFolderRulesBecomeExtraReadPaths", () => {
    const r = resolveFileTool("grep", { path: "." }, nested());
    expect(r.paths).toEqual([
      { need: "read", at: "." },
      { need: "read", at: "tree/vault" },
      { need: "read", at: "tree/noread" },
    ]);
    expect(resolveFileTool("ls", { path: "tree/vault" }, nested()).paths).toEqual([{ need: "read", at: "tree/vault" }]);
    expect(resolveFileTool("find", { path: "website" }, nested()).paths).toHaveLength(1);
  });
  it("verdictAndLabelsSeeTheNestedFolders", () => {
    const c = nested();
    const r = resolveFileTool("grep", { path: "." }, c);
    expect(readLabels(r, c.rules)).toContain("private");
    expect(decideLocal({ routeAllowed: true, resolved: r, rules: c.rules, classes: new Set() })).toBe("SCOPE_DENIED");
    const ok = resolveFileTool("grep", { path: "tree/vault" }, c);
    expect(decideLocal({ routeAllowed: true, resolved: ok, rules: c.rules, classes: new Set() })).toBe("OK");
    expect(readLabels(ok, c.rules)).toEqual(["private"]);
  });
  it("aNestedRefusedDirWithGrepDotIsScopeDenied", () => {
    const c = { ...ctx, refused: [canonical(join(ws, "secrets", "keys"))] };
    const r = resolveFileTool("grep", { path: "." }, c);
    expect(decideLocal({ routeAllowed: true, resolved: r, rules: c.rules, classes: new Set() })).toBe("SCOPE_DENIED");
  });
});

describe("case-insensitive volumes", () => {
  const c2 = () => ({
    ...ctx,
    rules: parseLocalRules({
      v: 1,
      folders: [
        { path: ".", access: ["read"] },
        { path: "notes", access: ["read", "write"], destination: "private" },
        { path: "notes/publish", access: ["read", "write"], destination: "public" },
      ],
      programs: [],
    }),
    refused: [join(ws, "secrets", "keys-later")],
  });
  it.skipIf(!caseInsensitive)("aTailThatMatchesARuleOnlyAfterFoldingIsUncheckable", () => {
    expect(resolvePathArg("notes/PUBLISH/x", "write", c2()).at).toBe("uncheckable");
    expect(resolvePathArg("notes/publish/x", "write", c2()).at).toBe("notes/publish/x");
  });
  it.skipIf(!caseInsensitive)("aTailThatMatchesARefusedEntryOnlyAfterFoldingIsRefused", () => {
    expect(resolvePathArg("secrets/KEYS-LATER/a", "read", c2()).at).toBe("refused");
  });
});

describe("absolute rules inside the workspace", () => {
  it("stillMatch", () => {
    const rs = parseLocalRules({
      v: 1,
      folders: [{ path: ".", access: ["read"] }, { path: join(ws, "notes"), access: ["read", "write"], destination: "private" }],
      programs: [],
    });
    const at = resolvePathArg("notes/a.md", "write", { ...ctx, rules: rs }).at;
    expect(at).toBe(join(ws, "notes", "a.md"));
    expect(folderRuleFor(at, rs)?.destination).toBe("private");
  });
});

describe("round 2: folding and rule locations", () => {
  const withRules = (folders: unknown[], refused: string[] = []) => ({
    ...ctx,
    rules: parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }, ...folders], programs: [] }),
    refused,
  });
  it.skipIf(!caseInsensitive)("aRuleSpelledInOtherCaseStillGovernsItsFolderUnderASearch", () => {
    const c = withRules([{ path: "TREE/Vault", access: ["read"], label: "private" }]);
    const r = resolveFileTool("grep", { path: "tree" }, c);
    expect(r.paths).toEqual([{ need: "read", at: "tree" }, { need: "read", at: "TREE/Vault" }]);
    expect(readLabels(r, c.rules)).toContain("private");
  });
  it.skipIf(!caseInsensitive)("aRuleBelowANonexistentSearchRootOnlyAfterFoldingIsUncheckable", () => {
    const c = withRules([{ path: "nope/x", access: ["read"], label: "private" }]);
    expect(resolveFileTool("find", { path: "NOPE" }, c).paths[0]?.at).toBe("uncheckable");
  });
  it("anNfdPathMatchingAnNfcRuleOnlyAfterFoldingIsUncheckable", () => {
    const c = withRules([{ path: "caf\u00e9", access: ["read", "write"], destination: "public" }]);
    expect(resolvePathArg("cafe\u0301/x", "write", c).at).toBe("uncheckable");
    expect(resolvePathArg("caf\u00e9/x", "write", c).at).toBe("caf\u00e9/x");
  });
  it("anNfdPathUnderAnNfcRefusedEntryIsRefused", () => {
    const c = withRules([], [join(ws, "r\u00e9sum\u00e9")]);
    expect(resolvePathArg("re\u0301sume\u0301/a", "read", c).at).toBe("refused");
  });
  it("aRuleSpelledThroughAnInWorkspaceSymlinkGovernsTheRealFolderAndIsRecordedInItsSpelling", () => {
    const c = withRules([{ path: "a/b", access: ["read", "write"], destination: "public" }]);
    const viaReal = resolvePathArg("c/b/x.md", "write", c);
    expect(viaReal.at).toBe("a/b/x.md");
    expect(folderRuleFor(viaReal.at, c.rules)?.destination).toBe("public");
    expect(resolvePathArg("a/b/x.md", "write", c).at).toBe("a/b/x.md");
    expect(resolvePathArg("c/other", "write", c).at).toBe("c/other");
  });
  it("aSearchOverTheRealFolderSeesARuleSpelledThroughTheSymlink", () => {
    const c = withRules([{ path: "a/b", access: ["read"], label: "private" }]);
    const r = resolveFileTool("grep", { path: "c" }, c);
    expect(r.paths).toEqual([{ need: "read", at: "c" }, { need: "read", at: "a/b" }]);
    expect(readLabels(r, c.rules)).toContain("private");
  });
});

describe("round 3: symlinks out, duplicate locations, root tie", () => {
  const withRules = (folders: unknown[]) => ({
    ...ctx,
    rules: parseLocalRules({ v: 1, folders, programs: [] }),
    refused: [],
  });
  const verdictOf = (at: string, need: "read" | "write", c: PathContext) =>
    decideLocal({ routeAllowed: true, resolved: { paths: [{ need, at }], programs: [], parse: "ok", readOnly: false }, rules: c.rules, classes: new Set() });
  it("aRelativeRuleThatSymlinksOutOfTheWorkspaceMatchesNothing", () => {
    const c = withRules([{ path: ".", access: ["read"] }, { path: "notes2", access: ["read", "write"], destination: "public" }]);
    const a = resolvePathArg(join(base, "out", "x"), "write", c);
    expect(a.at).toBe("outside");
    expect(verdictOf(a.at, "write", c)).toBe("SCOPE_DENIED");
  });
  it("aSymlinkUpAndBackOutIsOutside", () => {
    const c = withRules([{ path: ".", access: ["read", "write"], destination: "private" }, { path: "up/out", access: ["read", "write"], destination: "private" }]);
    const a = resolvePathArg("../out/f", "write", c);
    expect(a.at).toBe("outside");
    expect(verdictOf(a.at, "write", c)).toBe("SCOPE_DENIED");
  });
  it("twoRulesForTheSameRealFolderAreUncheckableInEitherOrder", () => {
    const real = { path: "c", access: ["read"] };
    const alias = { path: "a", access: ["read", "write"], destination: "public" };
    for (const folders of [[real, alias], [alias, real]]) {
      const c = withRules([{ path: ".", access: ["read"] }, ...folders]);
      const a = resolvePathArg("c/x", "write", c);
      expect(a.at).toBe("uncheckable");
      expect(verdictOf(a.at, "write", c)).toBe("UNCHECKABLE");
    }
  });
  it("anInWorkspacePathWithNoCoveringRuleKeepsItsRelativeAtAndIsDenied", () => {
    const c = withRules([{ path: "website", access: ["read"] }]);
    const a = resolvePathArg("src/x.ts", "read", c);
    expect(a.at).toBe("src/x.ts");
    expect(verdictOf(a.at, "read", c)).toBe("SCOPE_DENIED");
  });
  it("aNamedOneCharacterFolderBeatsTheRootInEitherOrder", () => {
    const root = { path: ".", access: ["read", "write"], destination: "public" };
    const s = { path: "s", access: ["read"], label: "private" };
    for (const folders of [[root, s], [s, root]]) {
      const c = withRules(folders);
      const w = resolvePathArg("s/x", "write", c);
      expect(w.at).toBe("s/x");
      expect(verdictOf(w.at, "write", c)).toBe("SCOPE_DENIED");
      expect(readLabels({ paths: [{ need: "read", at: w.at }], programs: [], parse: "ok", readOnly: true }, c.rules)).toContain("private");
    }
  });
});
