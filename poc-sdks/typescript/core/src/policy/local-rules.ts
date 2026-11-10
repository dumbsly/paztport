// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { posix } from "node:path";
import { encode } from "../encoding/b64url.ts";
import { sha256, utf8 } from "../crypto/crypto.ts";
import { canonicalize } from "../encoding/jcs.ts";
import { readFile, readToken, type JsonValue } from "../encoding/json.ts";
import { array, exactly, object } from "../internal/fields.ts";

/** What a folder rule lets a local tool call do under its path: read files, write them, or run a program there. */
export type FolderAccess = "read" | "write" | "exec";
/**
 * One folder of a client's local rules: its path (relative to the workspace, or absolute), what a call may do under
 * it, the class a read there records (`label`; a read of a folder with none records local-untrusted), and whether a
 * write there goes to a public or a private destination, which a rule that allows writing must say.
 */
export type FolderRule = {
  path: string;
  access: FolderAccess[];
  label?: "private" | "public" | "third-party";
  destination?: "public" | "private";
};
/**
 * A client's local rules (`rules.json`, pinned under the signed root as `rules:<rulesHash>`): its folders, and the
 * programs a call may run by name; NEVER_PROGRAMS stay refused even when listed.
 */
export type LocalRules = { v: 1; folders: FolderRule[]; programs: string[] };

/** Route prefix under which a session's local rules are pinned. */
export const RULES_ROUTE_PREFIX = "rules:";

/** Programs that can run other programs, write anywhere or reach the network; never allowed, even if listed. */
export const NEVER_PROGRAMS: readonly string[] = [
  "sh", "bash", "zsh", "dash", "ksh", "fish", "env", "xargs", "sudo", "su", "doas", "nohup", "timeout", "nice", "watch",
  "exec", "eval", "python", "python3", "node", "deno", "bun", "perl", "ruby", "php", "lua", "awk", "gawk", "sed", "find",
  "git", "make", "npm", "npx", "pip", "pip3", "osascript", "open", "xdg-open", "tee", "sort", "uniq",
  "script", "arch", "caffeinate", "busybox", "tar", "zip", "unzip", "rsync", "ssh", "scp", "sftp", "less", "more", "man", "vi", "vim",
  "nvim", "view", "emacs", "nano", "ed", "ex", "m4", "chroot", "setsid", "stdbuf", "flock", "rbash", "ash", "csh", "tcsh", "nodejs",
  "mawk", "nawk", "xcrun", "launchctl", "at", "batch", "crontab", "screen", "tmux", "expect", "gdb", "lldb", "dtrace", "sandbox-exec",
  "irb", "julia", "swift", "tclsh", "wish", "Rscript", "printf", "getopts",
  "time", "command", "lockf", "pydoc", "vimdiff", "rview", "rvim", "vimtutor",
];

/**
 * True when `name`, compared case-insensitively, is a NEVER_PROGRAMS entry or such an
 * entry followed only by a version suffix of digits, dots and dashes (python3.12, perl5.30, Bash).
 */
export function isNeverProgram(name: string): boolean {
  const lower = name.toLowerCase();
  return NEVER_PROGRAMS.some((entry) => lower.startsWith(entry.toLowerCase()) && /^[-0-9.]*$/.test(lower.slice(entry.length)));
}

const ACCESS: readonly string[] = ["read", "write", "exec"];
const LABELS: readonly string[] = ["private", "public", "third-party"];
const DESTINATIONS: readonly string[] = ["public", "private"];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bad(field: string, why: string): Error {
  return new Error(`invalid local rules: ${field}: ${why}`);
}

/** Path with `.` and `..` resolved and no trailing slash; relative paths stay relative. */
function normalPath(p: string): string {
  return posix.normalize(p);
}

/**
 * Throws unless value is well-formed local rules; returns a clean copy. For rules built in code, such as a policy
 * tool's from its paths file; rules read from bytes are read by readLocalRulesFile or readLocalRules, which also
 * refuse a member the rules do not define.
 */
export function parseLocalRules(value: unknown): LocalRules {
  if (!isObject(value)) {
    throw bad("rules", "must be an object");
  }
  if (value.v !== 1) {
    throw bad("v", "must be 1");
  }
  if (!Array.isArray(value.folders)) {
    throw bad("folders", "must be an array");
  }
  if (!Array.isArray(value.programs)) {
    throw bad("programs", "must be an array");
  }
  const seen = new Set<string>();
  const folders = value.folders.map((item: unknown, i): FolderRule => {
    const at = `folders[${i}]`;
    if (!isObject(item)) {
      throw bad(at, "must be an object");
    }
    if (typeof item.path !== "string" || item.path === "" || item.path.includes("\0")) {
      throw bad(`${at}.path`, "must be a non-empty string");
    }
    const norm = normalPath(item.path);
    if (!posix.isAbsolute(norm) && (norm === ".." || norm.startsWith("../"))) {
      throw bad(`${at}.path`, "must not leave the working folder");
    }
    const key = norm.length > 1 && norm.endsWith("/") ? norm.slice(0, -1) : norm;
    if (seen.has(key)) {
      throw bad(`${at}.path`, "duplicate folder");
    }
    seen.add(key);
    if (!Array.isArray(item.access) || item.access.length === 0) {
      throw bad(`${at}.access`, "must be a non-empty array");
    }
    for (const a of item.access) {
      if (typeof a !== "string" || !ACCESS.includes(a)) {
        throw bad(`${at}.access`, "must be read, write or exec");
      }
    }
    const access = item.access as FolderAccess[];
    if (new Set(access).size !== access.length) {
      throw bad(`${at}.access`, "must not repeat a value");
    }
    if (access.includes("write") && access.includes("exec")) {
      throw bad(`${at}.access`, "write and exec cannot be combined");
    }
    const out: FolderRule = { path: item.path, access: [...access] };
    if (item.label !== undefined) {
      if (typeof item.label !== "string" || !LABELS.includes(item.label)) {
        throw bad(`${at}.label`, "must be private, public or third-party");
      }
      out.label = item.label as FolderRule["label"];
    }
    if (item.destination !== undefined) {
      if (typeof item.destination !== "string" || !DESTINATIONS.includes(item.destination)) {
        throw bad(`${at}.destination`, "must be public or private");
      }
      out.destination = item.destination as FolderRule["destination"];
    }
    if (access.includes("write") && out.destination === undefined) {
      throw bad(`${at}.destination`, "required when access includes write");
    }
    return out;
  });
  const programs = value.programs.map((p: unknown, i): string => {
    const at = `programs[${i}]`;
    if (typeof p !== "string" || p === "") {
      throw bad(at, "must be a non-empty string");
    }
    if (p.includes("/") || p.includes("\0") || /\s/.test(p)) {
      throw bad(at, "must be a bare program name");
    }
    if (isNeverProgram(p)) {
      throw bad(at, `${p} is never allowed`);
    }
    return p;
  });
  return { v: 1, folders, programs };
}

/** The rules' schema: exactly `v`, `folders` and `programs`, each folder exactly its members; then parseLocalRules. */
function localRulesOf(value: JsonValue): LocalRules {
  const o = object(value);
  exactly(o, ["v", "folders", "programs"]);
  for (const folder of array(o, "folders")) exactly(object(folder), ["path", "access"], ["label", "destination"]);
  return parseLocalRules(o);
}

/**
 * Reads a rules file in any member order and spacing: MalformedJson for bytes that do not read, an Error naming the
 * member for rules the schema or parseLocalRules refuses.
 */
export function readLocalRulesFile(bytes: Uint8Array): LocalRules {
  return localRulesOf(readFile(bytes));
}

/** Reads local rules from their token, by readLocalRulesFile's rules. */
export function readLocalRules(token: string): LocalRules {
  return localRulesOf(readToken(token));
}

/** Hash that pins a rule set: base64url SHA-256 of "local-rules\n" + JCS(rules). */
export function rulesHash(rules: LocalRules): string {
  return encode(sha256(utf8("local-rules\n" + canonicalize(rules))));
}
