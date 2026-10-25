// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseLocalRules, type InfluenceClass } from "@paztport/path-attest";
import { decideLocal } from "../src/local/decide.ts";
import { parseBash, resolveBash, PINNED_PATH, READ_ONLY_PROGRAMS } from "../src/local/bash.ts";
import type { PathContext } from "../src/local/paths.ts";

const rules = parseLocalRules({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
    { path: "notes", access: ["read", "write"], destination: "private" },
  ],
  programs: ["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false", "mkdir", "touch", "cp", "mv"],
});

let base: string;
let ctx: PathContext & { pathDirs: readonly string[] };
const verdict = (cmd: string, classes: InfluenceClass[] = []) =>
  decideLocal({ routeAllowed: true, resolved: resolveBash(cmd, ctx), rules, classes: new Set(classes) });

beforeAll(() => {
  base = realpathSync.native(mkdtempSync(join(tmpdir(), "pz-bash-")));
  const ws = join(base, "ws");
  const bin = join(base, "bin");
  const bin2 = join(base, "bin2");
  for (const d of [ws, bin, bin2, join(ws, "website"), join(ws, "notes")]) mkdirSync(d, { recursive: true });
  for (const n of rules.programs) {
    if (n === "mv" || n === "touch") continue;
    writeFileSync(join(bin, n), "#!/bin/sh\n");
    chmodSync(join(bin, n), 0o755);
  }
  writeFileSync(join(bin, "mv"), "x"); // not executable
  mkdirSync(join(bin, "touch")); // a directory
  writeFileSync(join(bin2, "real-touch"), "#!/bin/sh\n");
  chmodSync(join(bin2, "real-touch"), 0o755);
  symlinkSync(join(bin2, "real-touch"), join(bin2, "touch")); // executable through a symlink
  for (const n of ["sort", "uniq", "bash", "curl"]) {
    writeFileSync(join(bin, n), "#!/bin/sh\n");
    chmodSync(join(bin, n), 0o755);
  }
  writeFileSync(join(ws, "website", "README.md"), "x");
  writeFileSync(join(ws, "notes", "a"), "x");
  writeFileSync(join(ws, "run.sh"), "x");
  chmodSync(join(ws, "run.sh"), 0o755);
  ctx = { cwd: ws, workspace: ws, rules, refused: [], pathDirs: [bin] };
});
afterAll(() => rmSync(base, { recursive: true, force: true }));

describe("parseBash accepts", () => {
  it("pipesAndLists", () => {
    const r = parseBash("cat a | wc -l && ls website");
    expect(r).toEqual({
      commands: [
        { argv: ["cat", "a"], redirects: [] },
        { argv: ["wc", "-l"], redirects: [] },
        { argv: ["ls", "website"], redirects: [] },
      ],
    });
  });
  it("quotesAndRedirects", () => {
    expect(parseBash('echo "a b" > website/x')).toEqual({ commands: [{ argv: ["echo", "a b"], redirects: [{ op: ">", target: "website/x" }] }] });
    expect(parseBash("echo 'a $b' \\$x")).toEqual({ commands: [{ argv: ["echo", "a $b", "$x"], redirects: [] }] });
    expect(parseBash('echo "a\\"b\\\\"')).toEqual({ commands: [{ argv: ["echo", 'a"b\\'], redirects: [] }] });
  });
  it("everyRedirectOperator", () => {
    const r = parseBash("a < i > o >> p 2> q 2>> r &> s 1> t 1>> u");
    expect(r).toEqual({
      commands: [{ argv: ["a"], redirects: [
        { op: "<", target: "i" }, { op: ">", target: "o" }, { op: ">>", target: "p" },
        { op: "2>", target: "q" }, { op: "2>>", target: "r" }, { op: "&>", target: "s" },
        { op: ">", target: "t" }, { op: ">>", target: "u" },
      ] }],
    });
  });
  it("fdDuplicationHasNoTarget", () => {
    for (const c of ["ls 2>&1", "ls >&2", "ls 1>&2", "ls > o 2>&1"]) {
      const r = parseBash(c);
      expect("commands" in r, c).toBe(true);
    }
    expect(parseBash("ls 2>&1")).toEqual({ commands: [{ argv: ["ls"], redirects: [] }] });
  });
  it("newlinesAndSemicolons", () => {
    const r = parseBash("a\n\nb; c;\n");
    expect(r).toEqual({ commands: [{ argv: ["a"], redirects: [] }, { argv: ["b"], redirects: [] }, { argv: ["c"], redirects: [] }] });
  });
  it("digitWordsThatAreNotFdPrefixes", () => {
    expect(parseBash("echo 2 > x")).toEqual({ commands: [{ argv: ["echo", "2"], redirects: [{ op: ">", target: "x" }] }] });
    expect(parseBash("echo a2>x")).toEqual({ commands: [{ argv: ["echo", "a2"], redirects: [{ op: ">", target: "x" }] }] });
  });
});

describe("parseBash refuses", () => {
  it.each([
    ["dollar", "cat $HOME/x"],
    ["dollarInDouble", 'cat "$HOME"'],
    ["escapedDollarInDouble", 'cat "\\$x"'],
    ["backtick", "cat `x`"],
    ["backtickInDouble", 'cat "`x`"'],
    ["procSubIn", "cat <(x)"],
    ["procSubOut", "cat >(x)"],
    ["heredoc", "cat <<EOF"],
    ["herestring", "cat <<< x"],
    ["background", "cat a &"],
    ["backgroundMid", "cat a & cat b"],
    ["paren", "(cat a)"],
    ["closeParen", "cat a)"],
    ["brace", "{ cat a; }"],
    ["braceWord", "cat a}"],
    ["star", "cat *"],
    ["question", "cat a?"],
    ["bracket", "cat [a]"],
    ["unterminatedSingle", "echo 'a"],
    ["unterminatedDouble", 'echo "a'],
    ["trailingBackslash", "echo a\\"],
    ["lineContinuation", "echo a\\\nb"],
    ["empty", ""],
    ["blank", "  \n "],
    ["leadingSemicolon", "; cat a"],
    ["doubleSemicolon", "cat a;; cat b"],
    ["trailingAnd", "cat a &&"],
    ["trailingPipe", "cat a |"],
    ["pipeNoLeft", "| cat a"],
    ["envAssignment", "FOO=bar cat a"],
    ["redirectNoTarget", "cat >"],
    ["redirectThenOperator", "cat > | x"],
    ["redirectOnly", "> x"],
    ["fdNine", "cat 3> x"],
    ["fdZeroOut", "cat 0> x"],
    ["dupToFile", "cat >&x"],
    ["dupToThree", "cat 2>&3"],
    ["readWrite", "cat <> x"],
    ["clobber", "cat >| x"],
    ["appendBoth", "cat &>> x"],
    ["pipeStderr", "cat |& wc"],
    ["history", "cat !x"],
    ["comment", "cat a #x"],
    ["tilde", "cat ~/x"],
    ["tildeUser", "cat ~root/x"],
    ["reservedWord", "if true; then cat a; fi"],
    ["emptyCommandName", "'' a"],
    ["nul", "cat a\0b"],
    ["stateBuiltin", "cd website"],
    ["dotSource", ". ./x"],
    ["emptyTarget", "cat > ''"],
  ])("%s", (_n, cmd) => {
    const r = parseBash(cmd);
    expect("error" in r, cmd).toBe(true);
  });
  it("allowsGlobCharactersWhenQuoted", () => {
    expect("commands" in parseBash("grep '*' 'a?' \"[x]\" \\* a")).toBe(true);
  });
});

describe("constants", () => {
  it("areThePinnedValues", () => {
    expect(PINNED_PATH).toBe("/usr/bin:/bin");
    expect(READ_ONLY_PROGRAMS).toEqual(["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false"]);
  });
});

describe("resolveBash", () => {
  it("catIsReadOnlyAndOk", () => {
    const r = resolveBash("cat website/README.md", ctx);
    expect(r.parse).toBe("ok");
    expect(r.readOnly).toBe(true);
    expect(r.paths).toContainEqual({ need: "read", at: "website/README.md" });
    expect(r.programs).toEqual([{ name: "cat", via: "list" }]);
    expect(verdict("cat website/README.md")).toBe("OK");
  });
  it("cwdIsAlwaysARead", () => {
    expect(resolveBash("pwd", ctx).paths).toEqual([{ need: "read", at: "." }]);
  });
  it("redirectWritesAreWritePaths", () => {
    const r = resolveBash("echo hi > website/CHANGELOG.md", ctx);
    expect(r.readOnly).toBe(false);
    expect(r.paths).toContainEqual({ need: "write", at: "website/CHANGELOG.md" });
    expect(verdict("echo hi > website/CHANGELOG.md")).toBe("OK");
  });
  it("inputRedirectIsARead", () => {
    const r = resolveBash("cat < website/README.md", ctx);
    expect(r.readOnly).toBe(true);
    expect(r.paths).toContainEqual({ need: "read", at: "website/README.md" });
  });
  it("writeRedirectOutsideAllowedFoldersIsDenied", () => {
    expect(verdict("echo hi > top.txt")).toBe("SCOPE_DENIED");
    expect(verdict("echo hi 2> /dev/null")).toBe("SCOPE_DENIED");
  });
  it("fdDuplicationAddsNoPathAndStaysReadOnly", () => {
    const r = resolveBash("ls website 2>&1", ctx);
    expect(r.readOnly).toBe(true);
    expect(r.paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "website" }]);
  });
  it("cpMakesBothWritePaths", () => {
    const r = resolveBash("cp notes/a website/b", ctx);
    expect(r.readOnly).toBe(false);
    expect(r.paths).toContainEqual({ need: "write", at: "notes/a" });
    expect(r.paths).toContainEqual({ need: "write", at: "website/b" });
    expect(verdict("cp notes/a website/b")).toBe("OK");
  });
  it("nonReadOnlyOptionsAreNotPathsButLongOptionValuesAre", () => {
    expect(resolveBash("mkdir -p notes/x", ctx).paths).toEqual([{ need: "read", at: "." }, { need: "write", at: "notes/x" }]);
    expect(resolveBash("cp --target-directory=website notes/a", ctx).paths).toContainEqual({ need: "write", at: "website" });
    expect(resolveBash("cp -tnotes/x a", ctx).paths).toContainEqual({ need: "write", at: "uncheckable" });
  });
  it("readOnlyArgumentIsAPathOnlyWhenItLooksLikeOneOrExists", () => {
    const r = resolveBash("grep needle run.sh", ctx);
    expect(r.paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "run.sh" }]);
    const r2 = resolveBash("grep -n needle", ctx);
    expect(r2.paths).toEqual([{ need: "read", at: "." }]);
    expect(resolveBash("grep --file=notes/a x", ctx).paths).toContainEqual({ need: "read", at: "notes/a" });
    expect(resolveBash("cat -- -x", ctx).paths).toEqual([{ need: "read", at: "." }]);
  });
  it("sortAndUniqAreNever", () => {
    expect(resolveBash("sort -o out website/README.md", ctx).programs).toEqual([{ name: "sort", via: "never" }]);
    expect(verdict("sort -o out website/README.md")).toBe("SCOPE_DENIED");
    expect(resolveBash("uniq a b", ctx).programs).toEqual([{ name: "uniq", via: "never" }]);
  });
  it("neverMatchesCaseAndVersionSpellingsAndPathedForms", () => {
    expect(resolveBash("Bash -c x", ctx).programs).toEqual([{ name: "Bash", via: "never" }]);
    expect(resolveBash("bash -c 'x'", ctx).programs).toEqual([{ name: "bash", via: "never" }]);
    expect(verdict("bash -c 'x'")).toBe("SCOPE_DENIED");
    expect(resolveBash("/bin/bash x", ctx).programs).toEqual([{ name: "/bin/bash", via: "never" }]);
  });
  it("unlistedOrMissingProgramsAreMissing", () => {
    expect(resolveBash("curl https://x", ctx).programs).toEqual([{ name: "curl", via: "missing" }]);
    expect(verdict("curl https://x")).toBe("SCOPE_DENIED");
  });
  it("aListedProgramMustBeAnExecutableRegularFileInPathDirs", () => {
    expect(resolveBash("mv a b", ctx).programs).toEqual([{ name: "mv", via: "missing" }]);
    expect(resolveBash("touch a", ctx).programs).toEqual([{ name: "touch", via: "missing" }]);
    const viaSymlink = { ...ctx, pathDirs: [join(base, "nope"), join(base, "bin2")] };
    expect(resolveBash("touch notes/a", viaSymlink).programs).toEqual([{ name: "touch", via: "list" }]);
    expect(resolveBash("cat x", { ...ctx, pathDirs: [] }).programs).toEqual([{ name: "cat", via: "missing" }]);
  });
  it("pathedProgramNeedsExecAccess", () => {
    const r = resolveBash("./run.sh", ctx);
    expect(r.paths).toContainEqual({ need: "exec", at: "run.sh" });
    expect(r.programs).toEqual([{ name: "./run.sh", via: "folder" }]);
    expect(r.readOnly).toBe(false);
    expect(verdict("./run.sh")).toBe("SCOPE_DENIED");
  });
  it("aPathedProgramInAnExecFolderIsOk", () => {
    const withExec = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read", "exec"] }], programs: [] });
    const c = { ...ctx, rules: withExec };
    const d = decideLocal({ routeAllowed: true, resolved: resolveBash("./run.sh", c), rules: withExec, classes: new Set() });
    expect(d).toBe("OK");
  });
  it("dotDotComponentsAreUncheckable", () => {
    expect(resolveBash("cat ../../etc/passwd", ctx).paths).toContainEqual({ need: "read", at: "uncheckable" });
    expect(verdict("cat ../../etc/passwd")).toBe("UNCHECKABLE");
    expect(verdict("cat website/../notes/a")).toBe("UNCHECKABLE");
    expect(verdict("echo x > website/../notes/a")).toBe("UNCHECKABLE");
    expect(verdict("cat ..")).toBe("UNCHECKABLE");
    expect(verdict("cat --file=../x")).toBe("UNCHECKABLE");
    expect(verdict("cat website/..x")).toBe("OK"); // no ".." component: an ordinary name
  });
  it("absolutePathsOutsideAreOutside", () => {
    expect(resolveBash("cat /etc/passwd", ctx).paths).toContainEqual({ need: "read", at: "outside" });
    expect(verdict("cat /etc/passwd")).toBe("SCOPE_DENIED");
  });
  it("parseErrorsAreUncheckable", () => {
    const r = resolveBash("cat $HOME/x", ctx);
    expect(r).toEqual({ paths: [], programs: [], parse: "error", readOnly: false });
    expect(verdict("cat $HOME/x")).toBe("UNCHECKABLE");
  });
  it("influenceFollowsDestinationAndClasses", () => {
    const both: InfluenceClass[] = ["private", "third-party"];
    expect(verdict("echo x >> website/CHANGELOG.md", both)).toBe("INFLUENCE_DENIED");
    expect(verdict("cat website/README.md", both)).toBe("OK");
  });
});
