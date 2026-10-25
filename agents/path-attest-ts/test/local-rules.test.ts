// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { NEVER_PROGRAMS, isNeverProgram, RULES_ROUTE_PREFIX, parseLocalRules, rulesHash } from "../src/local-rules.ts";

const demo = () => ({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
    { path: "notes", access: ["read", "write"], destination: "private" },
  ],
  programs: ["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false", "mkdir", "touch", "cp", "mv"],
});

function rejects(mutate: (r: ReturnType<typeof demo>) => void, message: RegExp): void {
  const r = demo();
  mutate(r);
  expect(() => parseLocalRules(r)).toThrow(message);
}

describe("parseLocalRules", () => {
  it("acceptsTheDemoRules", () => {
    expect(parseLocalRules(demo())).toEqual(demo());
  });

  it("acceptsAbsoluteAndExecOnlyFolders", () => {
    const r = parseLocalRules({ v: 1, folders: [{ path: "/opt/tools", access: ["read", "exec"] }], programs: [] });
    expect(r.folders[0]?.path).toBe("/opt/tools");
  });

  it("rejectsWriteAndExecTogether", () => {
    rejects((r) => { r.folders[1] = { path: "website", access: ["write", "exec"], destination: "public" } as never; }, /invalid local rules: folders\[1\]\.access/);
  });

  it("rejectsNeverProgramEvenIfListed", () => {
    rejects((r) => { r.programs.push("bash"); }, /invalid local rules: programs\[20\]/);
  });

  it("rejectsProgramWithSlash", () => {
    rejects((r) => { r.programs.push("bin/cat"); }, /invalid local rules: programs\[20\]/);
  });

  it("rejectsRelativePathEscapingUp", () => {
    rejects((r) => { r.folders.push({ path: "a/../../b", access: ["read"] }); }, /invalid local rules: folders\[3\]\.path/);
    rejects((r) => { r.folders.push({ path: "..", access: ["read"] }); }, /invalid local rules: folders\[3\]\.path/);
  });

  it("rejectsDuplicateFolderPaths", () => {
    rejects((r) => { r.folders.push({ path: "notes/", access: ["read"] }); }, /invalid local rules: folders\[3\]\.path/);
  });

  it("rejectsEmptyAccess", () => {
    rejects((r) => { r.folders[0] = { path: ".", access: [] }; }, /invalid local rules: folders\[0\]\.access/);
  });

  it("rejectsWriteWithoutDestination", () => {
    rejects((r) => { r.folders[2] = { path: "notes", access: ["write"] } as never; }, /invalid local rules: folders\[2\]\.destination/);
  });

  it("rejectsUnknownLabel", () => {
    rejects((r) => { (r.folders[1] as Record<string, unknown>).label = "secret"; }, /invalid local rules: folders\[1\]\.label/);
  });

  it("rejectsOtherVersions", () => {
    rejects((r) => { (r as Record<string, unknown>).v = 2; }, /invalid local rules: v/);
  });

  it("rejectsNonObjects", () => {
    expect(() => parseLocalRules(null)).toThrow(/invalid local rules/);
    expect(() => parseLocalRules([])).toThrow(/invalid local rules/);
  });
});

describe("NEVER_PROGRAMS", () => {
  it.each("sh bash zsh dash ksh fish env xargs sudo su doas nohup timeout nice watch exec eval python python3 node deno bun perl ruby php lua awk gawk sed find git make npm npx pip pip3 osascript open xdg-open tee sort uniq script arch caffeinate busybox tar zip unzip rsync ssh scp sftp less more man vi vim nvim view emacs nano ed ex m4 chroot setsid stdbuf flock rbash ash csh tcsh nodejs mawk nawk xcrun launchctl at batch crontab screen tmux expect gdb lldb dtrace sandbox-exec irb julia swift tclsh wish Rscript printf getopts time command lockf pydoc vimdiff rview rvim vimtutor".split(" "))(
    "contains %s",
    (name) => {
      expect(NEVER_PROGRAMS).toContain(name);
    },
  );
});

describe("rulesHash", () => {
  it("isStableUnderKeyOrder", () => {
    const a = parseLocalRules(demo());
    const b = parseLocalRules({ programs: demo().programs, folders: demo().folders.map((f) => ({ ...f })).reverse().reverse(), v: 1 });
    expect(rulesHash(a)).toBe(rulesHash(b));
  });

  it("changesWithFoldersOrPrograms", () => {
    const base = rulesHash(parseLocalRules(demo()));
    const f = demo();
    f.folders[0] = { path: ".", access: ["read", "exec"] };
    const p = demo();
    p.programs.pop();
    expect(rulesHash(parseLocalRules(f))).not.toBe(base);
    expect(rulesHash(parseLocalRules(p))).not.toBe(base);
  });

  it("hasARoutePrefix", () => {
    expect(RULES_ROUTE_PREFIX).toBe("rules:");
  });
});

describe("isNeverProgram", () => {
  it("matchesCaseAndVersionSpellings", () => {
    for (const n of ["bash", "Bash", "PYTHON3.12", "perl5.30", "python3", "sed", "rscript", "RSCRIPT4.1", "Tar", "zsh-5.9", "pydoc3.12"]) expect(isNeverProgram(n), n).toBe(true);
  });
  it("leavesOtherNamesAlone", () => {
    for (const n of ["env2x", "cat", "pythonx", "node-gyp", "sh-ish"]) expect(isNeverProgram(n), n).toBe(false);
  });
  it("parseLocalRulesRefusesTheseSpellings", () => {
    for (const n of ["Bash", "PYTHON3.12", "perl5.30"]) {
      const r = demo();
      r.programs.push(n);
      expect(() => parseLocalRules(r), n).toThrow(/is never allowed/);
    }
    const ok = demo();
    ok.programs.push("env2x");
    expect(() => parseLocalRules(ok)).not.toThrow();
  });
});
