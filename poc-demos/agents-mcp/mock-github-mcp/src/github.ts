// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

export type RepoFiles = Record<string, string>;

/** Null-prototype copy so paths like "__proto__" or "constructor" are ordinary keys. */
function cloneFiles(src: RepoFiles): RepoFiles {
  const out: RepoFiles = Object.create(null);
  for (const k of Object.keys(src)) Object.defineProperty(out, k, { value: src[k], writable: true, enumerable: true, configurable: true });
  return out;
}

function setFile(files: RepoFiles, path: string, content: string): void {
  Object.defineProperty(files, path, { value: content, writable: true, enumerable: true, configurable: true });
}
export type Issue = { number: number; title: string; body: string; author: string; state: "open" | "closed" };
export type PullRequest = { number: number; owner: string; repo: string; title: string; body: string; head: string; base: string };
export type Comment = { owner: string; repo: string; issue_number: number; body: string };

type RepoSeed = { owner: string; name: string; private: boolean; files: RepoFiles; issues: Issue[] };
type Repo = { private: boolean; branches: Map<string, RepoFiles>; issues: Issue[] };

export class GithubState {
  #repos = new Map<string, Repo>();
  #pulls: PullRequest[] = [];
  #comments: Comment[] = [];

  constructor(repos: RepoSeed[]) {
    for (const r of repos) {
      this.#repos.set(`${r.owner}/${r.name}`, {
        private: r.private,
        branches: new Map([["main", cloneFiles(r.files)]]),
        issues: r.issues.map((i) => ({ ...i })),
      });
    }
  }

  repo(owner: string, name: string): { private: boolean } | undefined {
    const r = this.#repos.get(`${owner}/${name}`);
    return r ? { private: r.private } : undefined;
  }

  branchFiles(owner: string, name: string, branch: string): RepoFiles | undefined {
    const f = this.#repos.get(`${owner}/${name}`)?.branches.get(branch);
    return f ? cloneFiles(f) : undefined;
  }

  pulls(): PullRequest[] {
    return this.#pulls.map((p) => ({ ...p }));
  }

  comments(): Comment[] {
    return this.#comments.map((c) => ({ ...c }));
  }

  /** Every repo as "owner/name" with its visibility, in insertion order. */
  listRepos(): { full: string; private: boolean }[] {
    return [...this.#repos].map(([full, r]) => ({ full, private: r.private }));
  }

  issues(owner: string, name: string): Issue[] | undefined {
    return this.#repos.get(`${owner}/${name}`)?.issues.map((i) => ({ ...i }));
  }

  /** Internal mutation helpers used by the tools; callers validate first. */
  createBranch(owner: string, name: string, branch: string, from: string): void {
    const r = this.#repos.get(`${owner}/${name}`)!;
    r.branches.set(branch, cloneFiles(r.branches.get(from)!));
  }

  putFiles(owner: string, name: string, branch: string, files: { path: string; content: string }[]): void {
    const target = this.#repos.get(`${owner}/${name}`)!.branches.get(branch)!;
    for (const f of files) setFile(target, f.path, f.content);
  }

  addPull(p: Omit<PullRequest, "number">): void {
    this.#pulls.push({ ...p, number: this.#pulls.length + 1 });
  }

  addComment(c: Comment): void {
    this.#comments.push({ ...c });
  }
}

export type ToolKind = "read" | "write";
export type ToolOutcome = {
  text: string;
  isError?: boolean;
  write?: { owner: string; repo: string; texts: string[] };
  read?: { owner: string; repo: string; what: "issues" | "file" | "repo-list"; includesPrivate: boolean };
};
export type GithubTool = {
  name: string;
  description: string;
  inputSchema: object;
  kind: ToolKind;
  run(state: GithubState, args: Record<string, unknown>): ToolOutcome;
  /** The strings a write tool would write, read leniently from raw args; read tools return []. */
  textsFromArgs(args: Record<string, unknown>): string[];
};

class ArgError extends Error {}

type Args = Record<string, unknown>;

function str(args: Args, key: string, required = true): string | undefined {
  const v = args[key];
  if (v === undefined || v === null) {
    if (required) throw new ArgError(`missing required parameter: ${key}`);
    return undefined;
  }
  if (typeof v !== "string") throw new ArgError(`parameter ${key} must be a string`);
  if (required && v === "") throw new ArgError(`missing required parameter: ${key}`);
  return v;
}

function req(args: Args, key: string): string {
  return str(args, key) as string;
}

function int(args: Args, key: string): number {
  const v = args[key];
  if (v === undefined || v === null) throw new ArgError(`missing required parameter: ${key}`);
  if (typeof v !== "number" || !Number.isInteger(v)) throw new ArgError(`parameter ${key} must be an integer`);
  return v;
}

function target(state: GithubState, args: Args): { owner: string; repo: string; private: boolean } {
  const owner = req(args, "owner");
  const repo = req(args, "repo");
  const r = state.repo(owner, repo);
  if (!r) throw new ArgError(`repository not found: ${owner}/${repo}`);
  return { owner, repo, private: r.private };
}

function branchOf(state: GithubState, owner: string, repo: string, branch: string) {
  const f = state.branchFiles(owner, repo, branch);
  if (!f) throw new ArgError(`branch not found: ${branch}`);
  return f;
}

function fileList(args: Args): { path: string; content: string }[] {
  const v = args["files"];
  if (v === undefined || v === null) throw new ArgError("missing required parameter: files");
  if (!Array.isArray(v) || v.length === 0) throw new ArgError("parameter files must be a non-empty array");
  return v.map((f, i) => {
    const o = f as { path?: unknown; content?: unknown } | null;
    if (typeof o !== "object" || o === null || typeof o.path !== "string" || o.path === "" || typeof o.content !== "string") {
      throw new ArgError(`files[${i}] must be an object with string path and content`);
    }
    return { path: o.path, content: o.content };
  });
}

/** Wraps a tool body so argument problems become tool errors instead of throws. */
function guarded(body: (state: GithubState, args: Args) => ToolOutcome): GithubTool["run"] {
  return (state, args) => {
    try {
      return body(state, args);
    } catch (e) {
      if (e instanceof ArgError) return { text: `Error: ${e.message}`, isError: true };
      throw e;
    }
  };
}

/** Lenient picker for raw (possibly malformed) args: string values of the given keys, in order. */
function pick(args: Args, keys: string[]): string[] {
  return keys.flatMap((k) => (typeof args[k] === "string" ? [args[k] as string] : []));
}

/** Lenient picker for raw push_files entries: every string `key` of each well-formed file object. */
function fileField(args: Args, key: "path" | "content"): string[] {
  const files = args["files"];
  if (!Array.isArray(files)) return [];
  return files.flatMap((f) => {
    const v = typeof f === "object" && f !== null ? (f as Record<string, unknown>)[key] : undefined;
    return typeof v === "string" ? [v] : [];
  });
}

const noTexts = (): string[] => [];

/** Per write tool: the strings it writes. Shared by tool.run (accepted writes) and the server (refused writes). */
const WRITE_TEXTS = {
  create_branch: (a: Args) => pick(a, ["branch"]),
  create_or_update_file: (a: Args) => pick(a, ["content", "message", "branch", "path"]),
  push_files: (a: Args) => [...fileField(a, "content"), ...fileField(a, "path"), ...pick(a, ["message", "branch"])],
  create_pull_request: (a: Args) => pick(a, ["title", "body"]),
  add_issue_comment: (a: Args) => pick(a, ["body"]),
};

function schema(properties: Record<string, object>, required: string[]): object {
  return { type: "object", properties, required };
}

const S = { type: "string" };
const OWNER = { ...S, description: "Repository owner" };
const REPO = { ...S, description: "Repository name" };

export const GITHUB_TOOLS: GithubTool[] = [
  {
    name: "list_issues",
    textsFromArgs: noTexts,
    description: "List issues in a GitHub repository.",
    kind: "read",
    inputSchema: schema({ owner: OWNER, repo: REPO, state: { ...S, enum: ["OPEN", "CLOSED"], description: "Filter by state" } }, ["owner", "repo"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const st = str(args, "state", false);
      const issues = state.issues(t.owner, t.repo)!.filter((i) => !st || i.state === st.toLowerCase());
      const text = issues.map((i) => `#${i.number} ${i.title} (by ${i.author}, ${i.state})\n${i.body}`).join("\n\n") || "No issues found.";
      return { text, read: { owner: t.owner, repo: t.repo, what: "issues", includesPrivate: t.private } };
    }),
  },
  {
    name: "issue_read",
    textsFromArgs: noTexts,
    description: "Get information about a specific issue in a GitHub repository.",
    kind: "read",
    inputSchema: schema({ method: { ...S, enum: ["get"], description: "Operation to perform" }, owner: OWNER, repo: REPO, issue_number: { type: "number", description: "Issue number" } }, ["method", "owner", "repo", "issue_number"]),
    run: guarded((state, args) => {
      const method = req(args, "method");
      if (method !== "get") throw new ArgError(`unsupported method: ${method}`);
      const t = target(state, args);
      const n = int(args, "issue_number");
      const i = state.issues(t.owner, t.repo)!.find((x) => x.number === n);
      if (!i) throw new ArgError(`issue not found: #${n}`);
      return {
        text: `#${i.number} ${i.title} (by ${i.author}, ${i.state})\n${i.body}`,
        read: { owner: t.owner, repo: t.repo, what: "issues", includesPrivate: t.private },
      };
    }),
  },
  {
    name: "get_file_contents",
    textsFromArgs: noTexts,
    description: "Get the contents of a file or list the files of a repository.",
    kind: "read",
    inputSchema: schema({ owner: OWNER, repo: REPO, path: { ...S, description: "Path to the file" }, ref: { ...S, description: "Branch name (default main)" } }, ["owner", "repo"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const path = str(args, "path", false);
      const ref = str(args, "ref", false) || "main";
      const files = branchOf(state, t.owner, t.repo, ref);
      const read = { owner: t.owner, repo: t.repo, what: "file" as const, includesPrivate: t.private };
      if (!path) return { text: Object.keys(files).join("\n"), read };
      if (!Object.hasOwn(files, path)) throw new ArgError(`file not found: ${path}`);
      return { text: files[path]!, read };
    }),
  },
  {
    name: "search_repositories",
    textsFromArgs: noTexts,
    description: "Find GitHub repositories by name, e.g. user:acme.",
    kind: "read",
    inputSchema: schema({ query: { ...S, description: "Repository search query" } }, ["query"]),
    run: guarded((state, args) => {
      const q = req(args, "query").toLowerCase().replace(/^(user|org):/, "");
      const hits = state.listRepos().filter((r) => r.full.toLowerCase().includes(q));
      const first = hits[0]?.full.split("/") ?? ["", ""];
      return {
        text: hits.map((r) => `${r.full} (${r.private ? "private" : "public"})`).join("\n") || "No repositories found.",
        read: { owner: first[0]!, repo: first[1]!, what: "repo-list", includesPrivate: hits.some((r) => r.private) },
      };
    }),
  },
  {
    name: "create_branch",
    textsFromArgs: WRITE_TEXTS.create_branch,
    description: "Create a new branch in a GitHub repository.",
    kind: "write",
    inputSchema: schema({ owner: OWNER, repo: REPO, branch: { ...S, description: "Name for the new branch" }, from_branch: { ...S, description: "Source branch (default main)" } }, ["owner", "repo", "branch"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const branch = req(args, "branch");
      const from = str(args, "from_branch", false) || "main";
      branchOf(state, t.owner, t.repo, from);
      if (state.branchFiles(t.owner, t.repo, branch)) throw new ArgError(`branch already exists: ${branch}`);
      state.createBranch(t.owner, t.repo, branch, from);
      return { text: `Created branch ${branch} from ${from}`, write: { owner: t.owner, repo: t.repo, texts: WRITE_TEXTS.create_branch(args) } };
    }),
  },
  {
    name: "create_or_update_file",
    textsFromArgs: WRITE_TEXTS.create_or_update_file,
    description: "Create or update a single file in a GitHub repository.",
    kind: "write",
    inputSchema: schema({ owner: OWNER, repo: REPO, path: { ...S, description: "Path to the file" }, content: { ...S, description: "File content" }, message: { ...S, description: "Commit message" }, branch: { ...S, description: "Branch to commit to" }, sha: { ...S, description: "Blob SHA of the file being replaced" } }, ["owner", "repo", "path", "content", "message", "branch"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const path = req(args, "path");
      const content = str(args, "content") ?? "";
      const message = req(args, "message");
      const branch = req(args, "branch");
      branchOf(state, t.owner, t.repo, branch);
      state.putFiles(t.owner, t.repo, branch, [{ path, content }]);
      return { text: `Committed ${path} to ${branch}`, write: { owner: t.owner, repo: t.repo, texts: WRITE_TEXTS.create_or_update_file(args) } };
    }),
  },
  {
    name: "push_files",
    textsFromArgs: WRITE_TEXTS.push_files,
    description: "Push multiple files to a GitHub repository in a single commit.",
    kind: "write",
    inputSchema: schema({ owner: OWNER, repo: REPO, branch: { ...S, description: "Branch to push to" }, files: { type: "array", items: { type: "object", properties: { path: S, content: S }, required: ["path", "content"] }, description: "Files to push" }, message: { ...S, description: "Commit message" } }, ["owner", "repo", "branch", "files", "message"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const branch = req(args, "branch");
      const files = fileList(args);
      const message = req(args, "message");
      branchOf(state, t.owner, t.repo, branch);
      state.putFiles(t.owner, t.repo, branch, files);
      return {
        text: `Pushed ${files.length} file(s) to ${branch}`,
        write: { owner: t.owner, repo: t.repo, texts: WRITE_TEXTS.push_files(args) },
      };
    }),
  },
  {
    name: "create_pull_request",
    textsFromArgs: WRITE_TEXTS.create_pull_request,
    description: "Create a new pull request in a GitHub repository.",
    kind: "write",
    inputSchema: schema({ owner: OWNER, repo: REPO, title: { ...S, description: "PR title" }, head: { ...S, description: "Branch containing changes" }, base: { ...S, description: "Branch to merge into" }, body: { ...S, description: "PR description" } }, ["owner", "repo", "title", "head", "base"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const title = req(args, "title");
      const head = req(args, "head");
      const base = req(args, "base");
      const body = str(args, "body", false) ?? "";
      branchOf(state, t.owner, t.repo, head);
      branchOf(state, t.owner, t.repo, base);
      state.addPull({ owner: t.owner, repo: t.repo, title, body, head, base });
      return { text: `Created pull request #${state.pulls().length}: ${title}`, write: { owner: t.owner, repo: t.repo, texts: WRITE_TEXTS.create_pull_request(args) } };
    }),
  },
  {
    name: "add_issue_comment",
    textsFromArgs: WRITE_TEXTS.add_issue_comment,
    description: "Add a comment to an issue in a GitHub repository.",
    kind: "write",
    inputSchema: schema({ owner: OWNER, repo: REPO, issue_number: { type: "number", description: "Issue number" }, body: { ...S, description: "Comment text" } }, ["owner", "repo", "issue_number", "body"]),
    run: guarded((state, args) => {
      const t = target(state, args);
      const n = int(args, "issue_number");
      const body = req(args, "body");
      if (!state.issues(t.owner, t.repo)!.some((i) => i.number === n)) throw new ArgError(`issue not found: #${n}`);
      state.addComment({ owner: t.owner, repo: t.repo, issue_number: n, body });
      return { text: `Added comment to #${n}`, write: { owner: t.owner, repo: t.repo, texts: WRITE_TEXTS.add_issue_comment(args) } };
    }),
  },
];
