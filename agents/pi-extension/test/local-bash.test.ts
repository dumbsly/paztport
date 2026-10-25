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
    const r = parseBash("a < i > o >> p 2> q 2>> r 1> t 1>> u");
    expect(r).toEqual({
      commands: [{ argv: ["a"], redirects: [
        { op: "<", target: "i" }, { op: ">", target: "o" }, { op: ">>", target: "p" },
        { op: "2>", target: "q" }, { op: "2>>", target: "r" },
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
    ["bothRedirect", "cat &> x"],
    ["tildeMidWord", "cat a~b"],
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
    expect(verdict("echo hi > /dev/null2")).toBe("SCOPE_DENIED");
  });
  it("devNullIsAllowedAndRecordsNoPath", () => {
    const r = resolveBash("ls website 2> /dev/null", ctx);
    expect(r.readOnly).toBe(true);
    expect(r.paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "website" }]);
    expect(verdict("cat website/README.md 2>/dev/null")).toBe("OK");
    expect(verdict("cat < /dev/null")).toBe("OK");
    expect(verdict("echo hi > /dev/null; cat website/README.md")).toBe("OK");
    expect(verdict("echo hi > /dev/nullx")).toBe("SCOPE_DENIED");
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
    expect(resolveBash("cp --target-directory=website notes/a", ctx).paths).toContainEqual({ need: "write", at: "uncheckable" });
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

  it("versionSuffixedAndPathedNeverNames", () => {
    expect(resolveBash("python3.12 x", ctx).programs).toEqual([{ name: "python3.12", via: "never" }]);
    expect(resolveBash("/usr/bin/Perl5.30 x", ctx).programs).toEqual([{ name: "/usr/bin/Perl5.30", via: "never" }]);
  });
  it("aListedNameThatLinksToAProgramRunnerIsNever", () => {
    const d = join(base, "bin3");
    mkdirSync(d, { recursive: true });
    symlinkSync(join(base, "bin", "bash"), join(d, "head"));
    expect(resolveBash("head a", { ...ctx, pathDirs: [d] }).programs).toEqual([{ name: "head", via: "never" }]);
  });
  it("optionsEndAtTheFirstOperandOrDoubleDash", () => {
    const w = (c: string) => resolveBash(c, ctx).paths.slice(1);
    expect(w("cp notes/a -evil")).toEqual([{ need: "write", at: "notes/a" }, { need: "write", at: "uncheckable" }, { need: "write", at: "-evil" }]);
    expect(w("cp notes/a --")).toEqual([{ need: "write", at: "notes/a" }, { need: "write", at: "--" }]);
    expect(w("mkdir -")).toEqual([{ need: "write", at: "-" }]);
    expect(w("mkdir -p -- -x")).toEqual([{ need: "write", at: "-x" }]);
    expect(w("cp -- notes/a website/b")).toEqual([{ need: "write", at: "notes/a" }, { need: "write", at: "website/b" }]);
    expect(w("cp -r -- -")).toEqual([{ need: "write", at: "-" }]);
    expect(verdict("mkdir -p website/x")).toBe("OK");
  });
  it("readOnlyOperandsAfterTheFirstOperandAreStillPaths", () => {
    writeFileSync(join(ctx.cwd, "-name"), "x");
    const r = resolveBash("cat run.sh -name", ctx);
    expect(r.paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "run.sh" }, { need: "read", at: "-name" }]);
    expect(resolveBash("cat -n run.sh", ctx).paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "run.sh" }]);
  });
  it("attachedShortOptionValues", () => {
    expect(resolveBash("cp -t. notes/a", ctx).paths).toContainEqual({ need: "write", at: "uncheckable" });
    expect(verdict("mv -t. notes/a")).toBe("UNCHECKABLE");
    expect(verdict("cp -r notes/a website/b")).toBe("OK");
    expect(resolveBash("grep -f.env x", ctx).paths).toContainEqual({ need: "read", at: ".env" });
    expect(resolveBash("grep -f/etc/x y", ctx).paths).toContainEqual({ need: "read", at: "outside" });
    expect(resolveBash("grep -fnotes/a y", ctx).paths).toContainEqual({ need: "read", at: "notes/a" });
    expect(resolveBash("diff -Xrun.sh a", ctx).paths).toContainEqual({ need: "read", at: "run.sh" });
    expect(resolveBash("head -n5 run.sh", ctx).paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "run.sh" }]);
  });
  it("variableAssigningBuiltinsAreRefused", () => {
    expect(verdict("printf -v PATH %s p; cat website/README.md")).toBe("UNCHECKABLE");
    expect(verdict("getopts p PATH -p")).toBe("UNCHECKABLE");
    for (const b of ["read", "shift", "fc", "history", "ulimit", "kill", "jobs", "times", "mapfile"]) expect(verdict(`${b} x`), b).toBe("UNCHECKABLE");
  });
  it("aCommandListWithAnEarlierWriteIsUncheckable", () => {
    expect(verdict("cp notes/a website/b && cat website/b")).toBe("UNCHECKABLE");
    expect(verdict("echo x > website/f; cat website/f")).toBe("UNCHECKABLE");
    expect(verdict("echo x > website/f | cat")).toBe("UNCHECKABLE");
    expect(verdict("echo x | cat > website/f")).toBe("OK");
    expect(verdict("cat website/README.md && cp notes/a website/b")).toBe("OK");
    expect(verdict("cat website/README.md | wc -l")).toBe("OK");
  });
});

describe("resolveBash subtrees", () => {
  const nested = parseLocalRules({
    v: 1,
    folders: [
      { path: ".", access: ["read"] },
      { path: "website", access: ["read", "write"], label: "public", destination: "public" },
      { path: "notes", access: ["read", "write"], label: "private", destination: "private" },
      { path: "notes/deep/vault", access: ["read"], label: "private" },
    ],
    programs: rules.programs,
  });
  it("aRefusedEntryBelowARecursiveRootIsRefused", () => {
    mkdirSync(join(ctx.cwd, "notes", "deep", "vault"), { recursive: true });
    mkdirSync(join(ctx.cwd, "notes", "secret"), { recursive: true });
    const c = { ...ctx, rules: nested, refused: [join(ctx.cwd, "notes", "secret")] };
    const r = resolveBash("grep -r KEY notes", c);
    expect(r.paths).toContainEqual({ need: "read", at: "refused" });
    expect(decideLocal({ routeAllowed: true, resolved: r, rules: nested, classes: new Set() })).toBe("SCOPE_DENIED");
    expect(resolveBash("ls -R .", c).paths).toContainEqual({ need: "read", at: "refused" });
  });
  it("aNestedFolderRuleBelowTheRootIsAnExtraPathWithTheSameNeed", () => {
    const c = { ...ctx, rules: nested };
    expect(resolveBash("grep -r KEY notes/deep", c).paths).toContainEqual({ need: "read", at: "notes/deep/vault" });
    expect(resolveBash("mv notes/deep website/n", c).paths).toContainEqual({ need: "write", at: "notes/deep/vault" });
    expect(resolveBash("cp -R notes website/n", c).paths).toContainEqual({ need: "write", at: "notes/deep/vault" });
    expect(resolveBash("echo x > notes/deep/f", c).paths).toContainEqual({ need: "write", at: "notes/deep/f" });
  });
});

describe("resolveBash option tokens in any position", () => {
  const at = (c: string) => resolveBash(c, ctx).paths;
  it("readOnlyProgramsJudgeAttachedValuesAfterOperandsAndAfterOptionArguments", () => {
    writeFileSync(join(ctx.cwd, ".env"), "x");
    expect(verdict("grep KEY website/README.md --file=.env")).toBe("OK"); // .env is a plain read in the root
    expect(at("grep KEY website/README.md --file=.env")).toContainEqual({ need: "read", at: ".env" });
    expect(at("grep KEY website/README.md -f.env")).toContainEqual({ need: "read", at: ".env" });
    expect(at("grep -e KEY -f.env website/README.md")).toContainEqual({ need: "read", at: ".env" });
    expect(at("grep KEY website/README.md -f/etc/passwd")).toContainEqual({ need: "read", at: "outside" });
    expect(verdict("grep KEY website/README.md -f/etc/passwd")).toBe("SCOPE_DENIED");
    expect(verdict("grep KEY website/README.md --file=/etc/passwd")).toBe("SCOPE_DENIED");
    expect(at("diff -L x -X.env a b")).toContainEqual({ need: "read", at: ".env" });
    expect(verdict("grep KEY website/README.md --file=../.env")).toBe("UNCHECKABLE");
  });
  it("aDashedTokenAfterTheOptionsEndedIsAlsoAnOperand", () => {
    writeFileSync(join(ctx.cwd, "-name"), "x");
    const p = at("cat run.sh -name");
    expect(p).toContainEqual({ need: "read", at: "-name" });
    expect(at("grep KEY run.sh --file=.env")).toContainEqual({ need: "read", at: ".env" });
  });
  it("programsThatMayWriteCannotCarryAttachedValuesAnywhere", () => {
    expect(verdict("cp notes/a -t/tmp")).toBe("UNCHECKABLE");
    expect(verdict("cp notes/a --target-directory=/tmp")).toBe("UNCHECKABLE");
    expect(verdict("cp --target-directory=/tmp notes/a")).toBe("UNCHECKABLE");
    expect(verdict("cp -e KEY notes/a -t/tmp")).toBe("UNCHECKABLE");
    expect(verdict("mkdir -p website/x")).toBe("OK");
  });
});

describe("resolveBash implicit working folder", () => {
  const nested = parseLocalRules({
    v: 1,
    folders: [
      { path: ".", access: ["read"] },
      { path: "website", access: ["read", "write"], label: "public", destination: "public" },
      { path: "notes", access: ["read", "write"], destination: "private" },
    ],
    programs: rules.programs,
  });
  it("recursiveGrepAndLsWithNoPathWalkTheWorkingFolder", () => {
    mkdirSync(join(ctx.cwd, "notes", "secret"), { recursive: true });
    const c = { ...ctx, rules: nested, refused: [join(ctx.cwd, "notes", "secret")] };
    for (const cmd of ["grep -r KEY", "grep -rn KEY", "grep --recursive KEY", "grep -d recurse KEY", "ls -R", "ls"]) {
      const r = resolveBash(cmd, c);
      expect(r.paths, cmd).toContainEqual({ need: "read", at: "refused" });
      expect(decideLocal({ routeAllowed: true, resolved: r, rules: nested, classes: new Set() }), cmd).toBe("SCOPE_DENIED");
    }
  });
  it("nestedFolderRulesBecomeExtraReadPaths", () => {
    const r = resolveBash("ls -R", ctx);
    expect(r.paths).toEqual([{ need: "read", at: "." }, { need: "read", at: "website" }, { need: "read", at: "notes" }]);
  });
  it("commandsThatCannotWalkTheFolderAreUnchanged", () => {
    expect(resolveBash("grep -n needle", ctx).paths).toEqual([{ need: "read", at: "." }]);
    expect(resolveBash("pwd", ctx).paths).toEqual([{ need: "read", at: "." }]);
    expect(resolveBash("cat < website/README.md", ctx).paths).not.toContainEqual({ need: "read", at: "notes" });
  });
});

