// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { requirement } from "@paztport/core";

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
  /**
   * The extensions this client requires of the server, as read: it calls the server only in an attested session whose
   * reply lists each of them (spec sessions.md, A client that requires extensions). Attested servers only.
   */
  requires?: string[];
  /** The switch that lets the client call the server without what it `requires`, as one with no requirement does. */
  continueWithoutRequired?: boolean;
};

export type PaztportConfig = {
  mode: ExtensionMode;
  clientDir: string;
  /** Where root.json, proofs-pi.json and rules.json are read from; defaults to clientDir. */
  clientPolicyDir?: string;
  servers: ServerSpec[];
  eventsLog?: string;
  /** Opt-in evidence file for offline re-verification; holds tool arguments and results. */
  evidenceLog?: string;
};

const MODES: readonly string[] = ["enforce", "no-root", "off"];
const SERVER_ID = /^[A-Za-z0-9_-]+$/;
const DEFAULT_PIN = "server-policy.pub";
const CONFIG_KEYS: readonly string[] = ["mode", "clientDir", "clientPolicyDir", "servers", "eventsLog", "evidenceLog"];
const SERVER_KEYS: readonly string[] = [
  "id", "command", "args", "env", "attested", "pin", "requires", "continueWithoutRequired",
];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Throws for the first member the loader does not define. A misplaced or misspelt key would otherwise configure
 * nothing, silently: a `requires` in the wrong place leaves the client calling the server with no requirement.
 */
function onlyKnownKeys(v: Record<string, unknown>, known: readonly string[], at: string): void {
  const unknown = Object.keys(v).find((k) => !known.includes(k));
  if (unknown !== undefined) {
    throw new Error(`config ${at}${unknown} is not a config key`);
  }
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
  onlyKnownKeys(v, SERVER_KEYS, `${at}.`);
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
  if (v.requires !== undefined) {
    if (!v.attested) {
      throw new Error(`config ${at}.requires needs an attested server: an unattested one opens no session to hold it`);
    }
    // a string is iterable too, so the SDK would read "influence" as nine one-letter names
    if (!Array.isArray(v.requires)) {
      throw new Error(`config ${at}.requires must be an array of extension names`);
    }
    try {
      requirement(v.requires);
    } catch (e) {
      throw new Error(`config ${at}.requires must be an array of extension names: ${(e as Error).message}`);
    }
    spec.requires = [...(v.requires as string[])];
  }
  if (v.continueWithoutRequired !== undefined) {
    if (typeof v.continueWithoutRequired !== "boolean") {
      throw new Error(`config ${at}.continueWithoutRequired must be a boolean`);
    }
    if (spec.requires === undefined || spec.requires.length === 0) {
      throw new Error(`config ${at}.continueWithoutRequired needs a non-empty requires, to continue without`);
    }
    spec.continueWithoutRequired = v.continueWithoutRequired;
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
  onlyKnownKeys(raw, CONFIG_KEYS, "");
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
  if (raw.clientPolicyDir !== undefined) {
    cfg.clientPolicyDir = resolve(dir, nonEmptyString(raw.clientPolicyDir, "clientPolicyDir"));
  }
  if (raw.eventsLog !== undefined) {
    cfg.eventsLog = resolve(dir, nonEmptyString(raw.eventsLog, "eventsLog"));
  }
  if (raw.evidenceLog !== undefined) {
    cfg.evidenceLog = resolve(dir, nonEmptyString(raw.evidenceLog, "evidenceLog"));
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
