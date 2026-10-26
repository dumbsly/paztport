// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PINNED_PATH } from "../src/local/bash.ts";
import { createGatedBash, shellEnv } from "../src/local/shell.ts";

/** The shell's own variables that `env` may add to the ones passed in. */
const SHELL_OWN = ["PWD", "SHLVL", "_", "OLDPWD"];
const ALLOWED = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "TZ", ...SHELL_OWN];

let cwd: string;
beforeAll(() => {
  cwd = realpathSync.native(mkdtempSync(join(tmpdir(), "pz-shell-")));
});
afterAll(() => rmSync(cwd, { recursive: true, force: true }));

async function run(command: string, env: Record<string, string> = {}): Promise<string> {
  for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
  try {
    const tool = createGatedBash(cwd);
    const out = await tool.execute("t", { command }, undefined, undefined, { cwd } as never);
    return out.content.map((c) => (c.type === "text" ? c.text : "")).join("");
  } finally {
    vi.unstubAllEnvs();
  }
}

describe("shellEnv", () => {
  it("dropsSecretsAndKeepsLang", () => {
    const env = shellEnv("/w", { ANTHROPIC_API_KEY: "a", GH_TOKEN: "b", SSH_AUTH_SOCK: "c", AWS_SECRET_ACCESS_KEY: "d", LANG: "C.UTF-8", PATH: "/evil" });
    expect(env).toEqual({ PATH: PINNED_PATH, HOME: "/w", TERM: "dumb", LANG: "C.UTF-8" });
  });

  it("keepsLocaleAndZoneWhenPresent", () => {
    expect(shellEnv("/w", { LC_ALL: "C", TZ: "UTC" })).toEqual({ PATH: PINNED_PATH, HOME: "/w", TERM: "dumb", LC_ALL: "C", TZ: "UTC" });
  });

  it("neverPassesShellBehaviourVariables", () => {
    const names = ["POSIXLY_CORRECT", "BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "IFS", "PS4", "SHELLOPTS", "BASHOPTS", "BASH_FUNC_f%%"];
    const from = Object.fromEntries(names.map((n) => [n, "x"]));
    const env = shellEnv("/w", from);
    for (const n of names) expect(Object.hasOwn(env, n)).toBe(false);
    expect(Object.keys(env).sort()).toEqual(["HOME", "PATH", "TERM"]);
  });
});

describe("createGatedBash", () => {
  it("isNamedBashAndKeepsPisSchema", () => {
    const tool = createGatedBash(cwd);
    expect(tool.name).toBe("bash");
    expect(JSON.stringify(tool.parameters)).toContain("command");
  });

  it("runsWithOnlyTheAllowlistedVariables", async () => {
    const out = await run("env | sort", { ANTHROPIC_API_KEY: "x", GH_TOKEN: "y", BASH_ENV: "/nope", IFS: "z" });
    const names = out.split("\n").filter((l) => l.includes("=")).map((l) => l.slice(0, l.indexOf("=")));
    expect(names.length).toBeGreaterThan(0);
    for (const n of names) expect(ALLOWED).toContain(n);
    expect(out).not.toContain("ANTHROPIC");
    expect(out).not.toContain("GH_TOKEN");
  });

  it("pinsPathAndHome", async () => {
    const out = await run("printenv PATH; printenv HOME; printenv TERM", { PATH_EXTRA: "1" });
    expect(out.trim().split("\n")).toEqual([PINNED_PATH, cwd, "dumb"]);
  });

  it("runsUnderBinSh", async () => {
    // with -c, $0 is the path the shell was started as (on macOS /bin/sh is bash in POSIX mode, so
    // BASH_VERSION says nothing here)
    expect((await run("echo $0")).trim()).toBe("/bin/sh");
  });

  it("ignoresACommandPrefixOrShellPathFromTheEnvironment", async () => {
    const out = await run("echo ok", { SHELL: "/bin/zsh", PI_SESSION_ID: "s" });
    expect(out.trim()).toBe("ok");
    expect(await run("printenv PI_SESSION_ID SHELL; echo $?")).toBe("1\n");
  });
});
