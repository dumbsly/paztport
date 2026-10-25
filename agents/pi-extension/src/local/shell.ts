// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createBashToolDefinition, createLocalBashOperations, type BashOperations, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { PINNED_PATH } from "./bash.ts";

/** Variables carried over from the parent when present: locale and time zone only. */
const CARRIED = ["LANG", "LC_ALL", "TZ"] as const;

/**
 * The environment a `bash` command runs with. It is built from an allowlist, so nothing else in
 * `from` (API keys, credentials, or variables that change how a shell behaves, such as BASH_ENV,
 * ENV, IFS or CDPATH) reaches the shell. HOME is the workspace.
 */
export function shellEnv(cwd: string, from: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { PATH: PINNED_PATH, HOME: cwd, TERM: "dumb" };
  for (const name of CARRIED) {
    const value = from[name];
    if (value !== undefined) {
      env[name] = value;
    }
  }
  return env;
}

/**
 * Paztport's `bash`: pi's tool with the same name, schema and output handling, but every command
 * runs under /bin/sh with the pinned PATH and the allowlisted environment, so programs resolve
 * against the PATH the gate checked. The environment the caller passes (pi's spawn hook, PI_*
 * variables) is ignored, and pi's commandPrefix and shellPath settings are not used.
 */
export function createGatedBash(cwd: string): ToolDefinition {
  const local = createLocalBashOperations({ shellPath: "/bin/sh" });
  const operations: BashOperations = {
    exec: (command, dir, options) => local.exec(command, dir, { ...options, env: shellEnv(cwd) }),
  };
  return createBashToolDefinition(cwd, { operations, exposeSessionEnvironment: false }) as unknown as ToolDefinition;
}
