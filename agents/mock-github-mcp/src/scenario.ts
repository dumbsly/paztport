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
};

/** agents/scenarios/github-issue-replay */
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

function parseSteps(v: unknown): Record<string, string> {
  const o = obj(v, "steps");
  const out: Record<string, string> = {};
  for (const [tool, phrase] of Object.entries(o)) {
    const field = `steps.${tool}`;
    const spec = GITHUB_TOOLS.find((t) => t.name === tool);
    if (!spec) bad(field, "is not a tool of the GitHub server");
    const text = nonEmpty(phrase, field);
    const args = Object.keys((spec.inputSchema as { properties: object }).properties);
    for (const m of text.matchAll(/\{([^{}]*)\}/g)) {
      if (!args.includes(m[1]!)) bad(field, `placeholder {${m[1]}} is not an argument of ${tool}`);
    }
    out[tool] = text;
  }
  return out;
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

  return {
    formatVersion: 1,
    id: nonEmpty(o.id, "id"),
    title: nonEmpty(o.title, "title"),
    description: nonEmpty(o.description, "description"),
    userPrompt: nonEmpty(o.userPrompt, "userPrompt"),
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
    steps: parseSteps(o.steps),
    tools: nonEmpty(o.tools, "tools"),
    serverId: nonEmpty(o.serverId, "serverId"),
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
