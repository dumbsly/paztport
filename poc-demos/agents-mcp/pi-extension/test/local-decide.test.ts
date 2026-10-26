// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { parseLocalRules, type InfluenceClass } from "@paztport/core";
import {
  decideLocal,
  folderRuleFor,
  readLabels,
  type Resolved,
  type ResolvedPath,
  type ResolvedProgram,
} from "../src/local/decide.ts";

const rules = parseLocalRules({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
    { path: "notes", access: ["read", "write"], destination: "private" },
  ],
  programs: ["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false", "mkdir", "touch", "cp", "mv"],
});

function resolved(paths: ResolvedPath[], programs: ResolvedProgram[] = [], extra: Partial<Resolved> = {}): Resolved {
  return { paths, programs, parse: "ok", readOnly: false, ...extra };
}
function verdict(r: Resolved, classes: InfluenceClass[] = [], routeAllowed = true, r2 = rules) {
  return decideLocal({ routeAllowed, resolved: r, rules: r2, classes: new Set(classes) });
}

describe("folderRuleFor", () => {
  it("picksTheLongestFolderAndMatchesWholeComponents", () => {
    expect(folderRuleFor("website/a.md", rules)?.path).toBe("website");
    expect(folderRuleFor("website", rules)?.path).toBe("website");
    expect(folderRuleFor("websites/a.md", rules)?.path).toBe(".");
    expect(folderRuleFor(".", rules)?.path).toBe(".");
    expect(folderRuleFor("src/x.ts", rules)?.path).toBe(".");
  });
  it("normalisesRulePathsAsWritten", () => {
    const r = parseLocalRules({
      v: 1,
      folders: [
        { path: "./site/", access: ["read", "write"], destination: "public" },
        { path: "/data/shared/", access: ["read"] },
      ],
      programs: [],
    });
    expect(folderRuleFor("site/x", r)?.path).toBe("./site/");
    expect(folderRuleFor("site", r)?.path).toBe("./site/");
    expect(folderRuleFor("other", r)).toBeUndefined();
    expect(folderRuleFor("/data/shared/a/b", r)?.path).toBe("/data/shared/");
    expect(folderRuleFor("/data/sharedx", r)).toBeUndefined();
  });
  it("keepsRelativeAndAbsoluteSpacesApart", () => {
    const r = parseLocalRules({ v: 1, folders: [{ path: "/data", access: ["read"] }, { path: "data", access: ["read"] }], programs: [] });
    expect(folderRuleFor("data/x", r)?.path).toBe("data");
    expect(folderRuleFor("/data/x", r)?.path).toBe("/data");
    expect(folderRuleFor("/etc/x", r)).toBeUndefined();
  });
  it("aNamedOneCharacterFolderBeatsTheRootInEitherOrder", () => {
    const root = { path: ".", access: ["read", "write"], destination: "public" };
    const s = { path: "s", access: ["read"], label: "private" };
    for (const folders of [[root, s], [s, root]]) {
      const r = parseLocalRules({ v: 1, folders, programs: [] });
      expect(folderRuleFor("s/x", r)?.path).toBe("s");
      expect(folderRuleFor("t/x", r)?.path).toBe(".");
    }
  });
  it("givesNothingForMarkersOrDotDot", () => {
    expect(folderRuleFor("outside", rules)).toBeUndefined();
    expect(folderRuleFor("refused", rules)).toBeUndefined();
    expect(folderRuleFor("uncheckable", rules)).toBeUndefined();
    expect(folderRuleFor("website/../x", rules)).toBeUndefined();
  });
});

describe("decideLocal", () => {
  const read = (at: string): ResolvedPath => ({ need: "read", at });
  const write = (at: string): ResolvedPath => ({ need: "write", at });

  it("routeNotAllowedWinsFirst", () => {
    expect(verdict(resolved([read("outside")], [], { parse: "error" }), [], false)).toBe("PATH_NOT_ALLOWED");
  });
  it("parseErrorOrUncheckableIsUncheckable", () => {
    expect(verdict(resolved([], [], { parse: "error" }))).toBe("UNCHECKABLE");
    expect(verdict(resolved([read("uncheckable")]))).toBe("UNCHECKABLE");
    expect(verdict(resolved([], [{ name: "x", via: "uncheckable" }]))).toBe("UNCHECKABLE");
    expect(verdict(resolved([read("outside"), read("uncheckable")]))).toBe("UNCHECKABLE");
  });
  it("outsideRefusedOrMissingAccessIsScopeDenied", () => {
    expect(verdict(resolved([read("outside")]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([read("refused")]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([write("src/a.ts")]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([{ need: "exec", at: "website/run" }]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([read("/etc/passwd")]))).toBe("SCOPE_DENIED");
  });
  it("neverOrMissingProgramIsScopeDenied", () => {
    expect(verdict(resolved([], [{ name: "bash", via: "never" }]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([], [{ name: "nope", via: "missing" }]))).toBe("SCOPE_DENIED");
    expect(verdict(resolved([], [{ name: "cat", via: "list" }, { name: "tool", via: "folder" }]))).toBe("OK");
  });
  it("publicWriteUnderPrivateAndUntrustedInfluenceIsDenied", () => {
    const w = resolved([write("website/a.md")]);
    expect(verdict(w, ["private"])).toBe("OK");
    expect(verdict(w, ["private", "third-party"])).toBe("INFLUENCE_DENIED");
    expect(verdict(w, ["private", "local-untrusted"])).toBe("INFLUENCE_DENIED");
    expect(verdict(w, ["third-party"])).toBe("OK");
  });
  it("privateDestinationIsOkUnderTheSameClasses", () => {
    expect(verdict(resolved([write("notes/a.md")]), ["private", "third-party"])).toBe("OK");
  });
  it("aWritableFolderWithoutDestinationIsNotPublic", () => {
    // parseLocalRules requires a destination for write folders, so build the shape directly.
    const r = { v: 1 as const, folders: [{ path: ".", access: ["read" as const, "write" as const] }], programs: [] };
    expect(verdict(resolved([write("a")]), ["private", "third-party"], true, r)).toBe("OK");
  });
  it("aReadOnlyFolderCannotBeWritten", () => {
    const r = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }], programs: [] });
    expect(verdict(resolved([write("a")]), ["private", "third-party"], true, r)).toBe("SCOPE_DENIED");
  });
  it("readOfPublicFolderUnderFullInfluenceIsOk", () => {
    expect(verdict(resolved([read("website/a.md")]), ["private", "third-party", "local-untrusted"])).toBe("OK");
  });
  it("emptyCommandIsOk", () => {
    expect(verdict(resolved([]))).toBe("OK");
  });
  it("theCallsOwnPrivateReadsCountWithTheSessionsInfluence", () => {
    // a single call that reads a private folder and writes a public one (cat priv/x > website/leak.md); bash
    // also reads its working folder, here an unlabelled root
    const r = parseLocalRules({
      v: 1,
      folders: [
        { path: ".", access: ["read"] },
        { path: "priv", access: ["read"], label: "private" },
        { path: "website", access: ["read", "write"], label: "public", destination: "public" },
      ],
      programs: ["cat", "grep"],
    });
    const copy = resolved([read("."), read("priv/x"), write("website/leak.md")], [{ name: "cat", via: "list" }]);
    expect(verdict(copy, ["third-party"], true, r)).toBe("INFLUENCE_DENIED");
    expect(verdict(copy, ["local-untrusted"], true, r)).toBe("INFLUENCE_DENIED");
    // with nothing untrusted in the session the copy is allowed, as the server allows a private read then a public
    // write: the call's own reads carry data, not instructions, so only their private label counts
    expect(verdict(copy, [], true, r)).toBe("OK");
    expect(verdict(copy, ["private"], true, r)).toBe("OK");
    // an unlabelled folder the call reads adds nothing: the model never saw that content, so it can't have steered the call
    expect(verdict(resolved([read("notes/u"), write("website/x")]), ["private"])).toBe("OK");
    expect(verdict(resolved([read("notes/u"), write("website/x")]), ["private", "third-party"])).toBe("INFLUENCE_DENIED");
  });
});

describe("readLabels", () => {
  it("returnsDistinctFolderLabelsOfReadPathsOnly", () => {
    const r = resolved([
      { need: "read", at: "website/a" },
      { need: "read", at: "website/b" },
      { need: "read", at: "src/x" },
      { need: "write", at: "notes/z" },
    ]);
    expect(readLabels(r, rules).sort()).toEqual(["local-untrusted", "public"]);
  });
  it("usesFolderLabelWhenSet", () => {
    const r = parseLocalRules({ v: 1, folders: [{ path: "secret", access: ["read"], label: "private" }], programs: [] });
    expect(readLabels(resolved([{ need: "read", at: "secret/k" }]), r)).toEqual(["private"]);
  });
});
