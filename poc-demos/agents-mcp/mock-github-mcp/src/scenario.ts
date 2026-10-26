// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { GITHUB_TOOLS, GithubState } from "./github.ts";
import type { Issue } from "./github.ts";

export type TaskCheck = { repo: string; file: string; absentLine: string; presentLine: string };

/** A data-only description of one replay: the repos, the planted issue, how to score the task. */
export type Scenario = {
  formatVersion: 1;
  id: string;
  title: string;
  description: string;
  userPrompt: string;
  /** Absolute after load. */
  payloadFile: string;
  plantedIssue: { repo: string; number: number; title: string; author: string };
  repos: {
    owner: string;
    name: string;
    private: boolean;
    files: Record<string, string>;
    issues: Issue[];
  }[];
  markers: string[];
  taskCheck: TaskCheck;
  /** Tool name -> plain phrase template; placeholders are argument names, e.g. "list the issues on {owner}/{repo}". */
  steps: Record<string, string>;
  /** The pi `--tools` value. */
  tools: string;
  serverId: string;
  /** Set with the three fields below, all or none. The mock server ignores them; the eval runner uses them. */
  localTools?: true;
  /** Files seeded into the run's workspace (paths relative to it) and the folders that count as public. */
  workspace?: { files: Record<string, string>; publicFolders: string[] };
  /** The folder under `<demo>/client/` that holds this scenario's local-tools policy. */
  clientPolicy?: string;
  /** `changelog` is a workspace-relative path under one of the public folders. */
  localTaskCheck?: { changelog: string; readme: TaskCheck };
};

/** pi's built-in tools (a copy of the list in pi-extension/src/local/gate.ts; the eval does not import the extension). */
export const BUILTIN_LOCAL_TOOLS: readonly string[] = ["read", "write", "edit", "bash", "grep", "find", "ls", "powershell"];
/** Placeholders a local tool's phrase may use: the argument names of pi's built-in tools. */
const LOCAL_STEP_ARGS: Record<string, string[]> = {
  read: ["path"],
  write: ["path"],
  edit: ["path"],
  bash: ["command"],
  grep: ["pattern", "path"],
  find: ["pattern", "path"],
  ls: ["path"],
  powershell: ["command"],
};

/** poc-demos/agents-mcp/scenarios/github-issue-replay */
export const BUILTIN_SCENARIO_DIR: string = join(import.meta.dirname, "../../scenarios/github-issue-replay");

class ScenarioError extends Error {}

function bad(field: string, why: string): never {
  throw new ScenarioError(`invalid scenario: ${field}: ${why}`);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function obj(v: unknown, field: string): Record<string, unknown> {
  if (!isObject(v)) bad(field, "must be an object");
  return v;
}

function arr(v: unknown, field: string): unknown[] {
  if (!Array.isArray(v)) bad(field, "must be an array");
  return v;
}

function nonEmpty(v: unknown, field: string): string {
  if (typeof v !== "string" || v === "") bad(field, "must be a non-empty string");
  return v;
}

function integer(v: unknown, field: string): number {
  if (typeof v !== "number" || !Number.isInteger(v)) bad(field, "must be an integer");
  return v;
}

function parseIssue(v: unknown, field: string): Issue {
  const o = obj(v, field);
  const state = o.state;
  if (state !== "open" && state !== "closed") bad(`${field}.state`, 'must be "open" or "closed"');
  if (typeof o.body !== "string") bad(`${field}.body`, "must be a string");
  return {
    number: integer(o.number, `${field}.number`),
    title: nonEmpty(o.title, `${field}.title`),
    body: o.body,
    author: nonEmpty(o.author, `${field}.author`),
    state,
  };
}

function parseSteps(v: unknown, localTools: boolean): Record<string, string> {
  const o = obj(v, "steps");
  const out: Record<string, string> = {};
  for (const [tool, phrase] of Object.entries(o)) {
    const field = `steps.${tool}`;
    const spec = GITHUB_TOOLS.find((t) => t.name === tool);
    const local = localTools ? LOCAL_STEP_ARGS[tool] : undefined;
    if (!spec && !local) bad(field, "is not a tool of the GitHub server");
    const text = nonEmpty(phrase, field);
    const args = spec ? Object.keys((spec.inputSchema as { properties: object }).properties) : local!;
    for (const m of text.matchAll(/\{([^{}]*)\}/g)) {
      if (!args.includes(m[1]!)) bad(field, `placeholder {${m[1]}} is not an argument of ${tool}`);
    }
    out[tool] = text;
  }
  return out;
}

/** pi reads a message argument that starts with "@" as a file to include, even after `--`. */
function userPrompt(v: unknown): string {
  const text = nonEmpty(v, "userPrompt");
  if (text.startsWith("@")) bad("userPrompt", 'must not start with "@" (pi would read it as a file)');
  return text;
}

/** The pi `--tools` value: a comma-separated list in which every entry names a tool of this scenario's server. */
function parseTools(v: unknown, serverId: string, localTools: boolean): string {
  const text = nonEmpty(v, "tools");
  // pi names a tool mcp__<id>__<tool>, with every character outside [A-Za-z0-9_] replaced by "_"
  const prefix = `mcp__${serverId}__`.replace(/[^A-Za-z0-9_]/g, "_");
  for (const entry of text.split(",")) {
    if (localTools && BUILTIN_LOCAL_TOOLS.includes(entry)) continue;
    if (!entry.startsWith(prefix)) bad("tools", `every entry must start with ${prefix}${localTools ? " or name a built-in tool" : ""} (got "${entry}")`);
  }
  return text;
}

/** A workspace-relative path: not absolute, no ".." part, no empty part. Returns it normalised (no trailing slash). */
function relPath(v: unknown, field: string): string {
  const text = nonEmpty(v, field);
  if (isAbsolute(text) || text.startsWith("/")) bad(field, `"${text}" must be a relative path`);
  const parts = text.split("/");
  if (parts.some((p) => p === ".." || p === "" || p === ".")) bad(field, `"${text}" must not contain "..", "." or empty parts`);
  return parts.join("/");
}

/** The four local-tools fields, all or none. */
function parseLocal(o: Record<string, unknown>): Pick<Scenario, "localTools" | "workspace" | "clientPolicy" | "localTaskCheck"> {
  const names = ["localTools", "workspace", "clientPolicy", "localTaskCheck"] as const;
  const present = names.filter((k) => o[k] !== undefined);
  if (present.length === 0) return {};
  for (const k of names) if (o[k] === undefined) bad(k, `is required when ${present[0]} is set (the local-tools fields come together)`);
  if (o.localTools !== true) bad("localTools", "must be true");
  const clientPolicy = nonEmpty(o.clientPolicy, "clientPolicy");
  if (!/^[a-z0-9-]+$/.test(clientPolicy)) bad("clientPolicy", "must match [a-z0-9-]+");

  const w = obj(o.workspace, "workspace");
  const filesRaw = obj(w.files, "workspace.files");
  const files: Record<string, string> = {};
  for (const [path, text] of Object.entries(filesRaw)) {
    relPath(path, "workspace.files");
    if (typeof text !== "string") bad("workspace.files", `the text of ${path} must be a string`);
    files[path] = text;
  }
  const publicFolders = arr(w.publicFolders, "workspace.publicFolders").map((f, i) => relPath(f, `workspace.publicFolders[${i}]`));
  if (publicFolders.length === 0) bad("workspace.publicFolders", "must not be empty");

  const c = obj(o.localTaskCheck, "localTaskCheck");
  const changelog = relPath(c.changelog, "localTaskCheck.changelog");
  if (!publicFolders.some((f) => changelog.startsWith(`${f}/`))) bad("localTaskCheck.changelog", `must lie under one of the public folders (${publicFolders.join(", ")})`);
  const r = obj(c.readme, "localTaskCheck.readme");
  const readmeFile = relPath(r.file, "localTaskCheck.readme.file");
  for (const [field, path] of [["localTaskCheck.changelog", changelog], ["localTaskCheck.readme.file", readmeFile]] as const) {
    if (!Object.hasOwn(files, path)) bad(field, `"${path}" is not one of the workspace files`);
  }
  return {
    localTools: true,
    workspace: { files, publicFolders },
    clientPolicy,
    localTaskCheck: {
      changelog,
      readme: {
        repo: nonEmpty(r.repo, "localTaskCheck.readme.repo"),
        file: readmeFile,
        absentLine: nonEmpty(r.absentLine, "localTaskCheck.readme.absentLine"),
        presentLine: nonEmpty(r.presentLine, "localTaskCheck.readme.presentLine"),
      },
    },
  };
}

/** Reads and checks `<dir>/scenario.json`. Throws an Error that names the first bad field. */
export function loadScenario(dir: string): Scenario {
  const file = join(dir, "scenario.json");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    throw new ScenarioError(`cannot read ${file}: ${(e as Error).message}`);
  }
  const o = obj(raw, "scenario.json");
  if (o.formatVersion !== 1) bad("formatVersion", "must be 1");

  const payloadName = nonEmpty(o.payloadFile, "payloadFile");
  const payloadFile = resolve(dir, payloadName);
  const rel = relative(resolve(dir), payloadFile);
  if (isAbsolute(payloadName) || rel === "" || rel.startsWith("..") || isAbsolute(rel)) bad("payloadFile", "must name a file inside the scenario folder");
  try {
    readFileSync(payloadFile, "utf8");
  } catch (e) {
    bad("payloadFile", `cannot read ${payloadFile}: ${(e as Error).message}`);
  }

  const repos = arr(o.repos, "repos").map((v, i) => {
    const f = `repos[${i}]`;
    const r = obj(v, f);
    if (typeof r.private !== "boolean") bad(`${f}.private`, "must be a boolean");
    const filesRaw = obj(r.files, `${f}.files`);
    const files: Record<string, string> = {};
    for (const [path, text] of Object.entries(filesRaw)) {
      if (path === "") bad(`${f}.files`, "has an empty path");
      if (typeof text !== "string") bad(`${f}.files`, `the text of ${path} must be a string`);
      files[path] = text;
    }
    return {
      owner: nonEmpty(r.owner, `${f}.owner`),
      name: nonEmpty(r.name, `${f}.name`),
      private: r.private,
      files,
      issues: arr(r.issues, `${f}.issues`).map((x, j) => parseIssue(x, `${f}.issues[${j}]`)),
    };
  });
  if (repos.length === 0) bad("repos", "must not be empty");
  const known = new Set(repos.map((r) => `${r.owner}/${r.name}`));
  if (known.size !== repos.length) bad("repos", "has a repository listed twice");

  const p = obj(o.plantedIssue, "plantedIssue");
  const plantedRepo = nonEmpty(p.repo, "plantedIssue.repo");
  if (!known.has(plantedRepo)) bad("plantedIssue.repo", `${plantedRepo} is not one of the repos`);
  const plantedNumber = integer(p.number, "plantedIssue.number");
  const home = repos.find((r) => `${r.owner}/${r.name}` === plantedRepo)!;
  if (home.issues.some((i) => i.number === plantedNumber)) bad("plantedIssue.number", `#${plantedNumber} already exists in ${plantedRepo}`);

  const markers = arr(o.markers, "markers").map((m, i) => nonEmpty(m, `markers[${i}]`));

  const t = obj(o.taskCheck, "taskCheck");
  const taskRepo = nonEmpty(t.repo, "taskCheck.repo");
  if (!known.has(taskRepo)) bad("taskCheck.repo", `${taskRepo} is not one of the repos`);

  const serverId = nonEmpty(o.serverId, "serverId");
  // the mock server checks every signed call against the name "github"; until it takes the name as a
  // parameter, any other name would make every signed call fail
  if (serverId !== "github") bad("serverId", "the mock GitHub server only accepts serverId github");
  const local = parseLocal(o);
  if (local.localTaskCheck && !known.has(local.localTaskCheck.readme.repo)) bad("localTaskCheck.readme.repo", `${local.localTaskCheck.readme.repo} is not one of the repos`);
  const tools = parseTools(o.tools, serverId, local.localTools === true);

  return {
    formatVersion: 1,
    id: nonEmpty(o.id, "id"),
    title: nonEmpty(o.title, "title"),
    description: nonEmpty(o.description, "description"),
    userPrompt: userPrompt(o.userPrompt),
    payloadFile,
    plantedIssue: { repo: plantedRepo, number: plantedNumber, title: nonEmpty(p.title, "plantedIssue.title"), author: nonEmpty(p.author, "plantedIssue.author") },
    repos,
    markers,
    taskCheck: {
      repo: taskRepo,
      file: nonEmpty(t.file, "taskCheck.file"),
      absentLine: nonEmpty(t.absentLine, "taskCheck.absentLine"),
      presentLine: nonEmpty(t.presentLine, "taskCheck.presentLine"),
    },
    steps: parseSteps(o.steps, local.localTools === true),
    tools,
    serverId,
    ...local,
  };
}

/**
 * The repos of a scenario as a fresh GithubState. `{{CANARY}}` in any file text becomes the canary;
 * the planted issue is added to its repo with `issuePayload` as its body, unless that is null.
 */
export function scenarioFixtures(s: Scenario, opts: { canary: string; issuePayload: string | null }): GithubState {
  return new GithubState(
    s.repos.map((r) => {
      const files: Record<string, string> = {};
      for (const [path, text] of Object.entries(r.files)) files[path] = text.split("{{CANARY}}").join(opts.canary);
      const issues = r.issues.map((i) => ({ ...i }));
      if (opts.issuePayload !== null && `${r.owner}/${r.name}` === s.plantedIssue.repo) {
        issues.push({ number: s.plantedIssue.number, title: s.plantedIssue.title, body: opts.issuePayload, author: s.plantedIssue.author, state: "open" });
      }
      return { owner: r.owner, name: r.name, private: r.private, files, issues };
    }),
  );
}
