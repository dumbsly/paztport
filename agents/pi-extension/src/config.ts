// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export type ExtensionMode = "enforce" | "no-root" | "off";

export type ServerSpec = {
  /** Matches ^[A-Za-z0-9_-]+$: no ".", "/" or "|", which are separators in routes and tool names. */
  id: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
  attested: boolean;
  /** Path to the server policy public key file; defaults to <clientDir>/server-policy.pub when attested. */
  pin?: string;
};

export type PaztportConfig = {
  mode: ExtensionMode;
  clientDir: string;
  servers: ServerSpec[];
  eventsLog?: string;
};

const MODES: readonly string[] = ["enforce", "no-root", "off"];
const SERVER_ID = /^[A-Za-z0-9_-]+$/;
const DEFAULT_PIN = "server-policy.pub";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: unknown, field: string): string {
  if (typeof v !== "string" || v === "") {
    throw new Error(`config ${field} must be a non-empty string`);
  }
  return v;
}

function parseServer(v: unknown, i: number, dir: string, clientDir: string, seen: Set<string>): ServerSpec {
  const at = `servers[${i}]`;
  if (!isObject(v)) {
    throw new Error(`config ${at} must be an object`);
  }
  const id = nonEmptyString(v.id, `${at}.id`);
  if (!SERVER_ID.test(id)) {
    throw new Error(`config ${at}.id must match ${SERVER_ID.source}`);
  }
  if (seen.has(id)) {
    throw new Error(`config ${at}.id duplicates server id ${id}`);
  }
  seen.add(id);
  const command = nonEmptyString(v.command, `${at}.command`);
  if (typeof v.attested !== "boolean") {
    throw new Error(`config ${at}.attested must be a boolean`);
  }
  const spec: ServerSpec = { id, command, attested: v.attested };
  if (v.args !== undefined) {
    if (!Array.isArray(v.args) || !v.args.every((a) => typeof a === "string")) {
      throw new Error(`config ${at}.args must be an array of strings`);
    }
    spec.args = [...v.args];
  }
  if (v.env !== undefined) {
    if (!isObject(v.env) || !Object.values(v.env).every((e) => typeof e === "string")) {
      throw new Error(`config ${at}.env must be an object of strings`);
    }
    spec.env = Object.fromEntries(Object.entries(v.env)) as Record<string, string>;
  }
  if (v.pin !== undefined) {
    spec.pin = resolve(dir, nonEmptyString(v.pin, `${at}.pin`));
  } else if (v.attested) {
    spec.pin = join(clientDir, DEFAULT_PIN);
  }
  return spec;
}

/** Reads and validates the JSON config; relative paths resolve against the config file's directory. */
export function loadConfig(path: string): PaztportConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`cannot read config ${path}: ${(e as Error).message}`);
  }
  if (!isObject(raw)) {
    throw new Error("config must be a JSON object");
  }
  const dir = dirname(resolve(path));
  if (typeof raw.mode !== "string" || !MODES.includes(raw.mode)) {
    throw new Error(`config mode must be one of ${MODES.join(", ")}`);
  }
  const clientDir = resolve(dir, nonEmptyString(raw.clientDir, "clientDir"));
  if (!Array.isArray(raw.servers)) {
    throw new Error("config servers must be an array");
  }
  const seen = new Set<string>();
  const servers = raw.servers.map((s: unknown, i: number) => parseServer(s, i, dir, clientDir, seen));
  const cfg: PaztportConfig = { mode: raw.mode as ExtensionMode, clientDir, servers };
  if (raw.eventsLog !== undefined) {
    cfg.eventsLog = resolve(dir, nonEmptyString(raw.eventsLog, "eventsLog"));
  }
  return cfg;
}

/** The --paztport-config flag value first, then PAZTPORT_CONFIG; empty strings count as unset. */
export function resolveConfigPath(flag: string | undefined, env: NodeJS.ProcessEnv): string | undefined {
  if (flag !== undefined && flag !== "") {
    return flag;
  }
  const fromEnv = env.PAZTPORT_CONFIG;
  return fromEnv !== undefined && fromEnv !== "" ? fromEnv : undefined;
}

/**
 * realpath of a path that may not exist yet: the realpath of its nearest existing ancestor, with the
 * missing rest appended (it holds no symlinks, since it does not exist).
 */
function realpathOfNearest(path: string): string {
  let p = resolve(path);
  const rest: string[] = [];
  for (;;) {
    try {
      return join(realpathSync.native(p), ...rest);
    } catch (e) {
      const parent = dirname(p);
      if (parent === p) {
        throw e;
      }
      rest.unshift(basename(p));
      p = parent;
    }
  }
}

/**
 * Throws when realpath(path) equals or is under realpath(cwd): keys, pins and the config must stay out
 * of the agent's reach. `what` names the path in errors. With `mayBeMissing`, a path that does not
 * exist yet is judged by where it would be; otherwise it must exist.
 */
export function assertOutsideWorkspace(path: string, cwd: string, what = "clientDir", opts: { mayBeMissing?: boolean } = {}): void {
  let target: string;
  let ws: string;
  try {
    target = opts.mayBeMissing === true ? realpathOfNearest(path) : realpathSync.native(path);
  } catch (e) {
    throw new Error(`${what} ${path} cannot be resolved: ${(e as Error).message}`);
  }
  try {
    ws = realpathSync.native(cwd);
  } catch (e) {
    throw new Error(`workspace ${cwd} cannot be resolved: ${(e as Error).message}`);
  }
  const rel = relative(ws, target);
  const outside = rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel);
  if (!outside) {
    throw new Error(`${what} ${path} is inside the workspace ${cwd}; keep it outside`);
  }
}
