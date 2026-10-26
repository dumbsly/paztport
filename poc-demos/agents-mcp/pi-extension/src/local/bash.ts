// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A strict, hand-written parser for the small subset of `bash` the local gate can
// check, and the resolution of a command's programs and paths. Conservative, not a
// guarantee: whatever cannot be resolved statically is refused, never guessed.

import { accessSync, constants, lstatSync, realpathSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { isNeverProgram } from "@paztport/core";
import type { Need, Resolved, ResolvedPath, ResolvedProgram } from "./decide.ts";
import { canonical, resolvePathArg, withSubtree, WALK_LIMIT, type PathContext } from "./paths.ts";

export type Redirect = { op: "<" | ">" | ">>" | "2>" | "2>>" | "&>"; target: string };
export type SimpleCommand = { argv: string[]; redirects: Redirect[] };

/** The PATH the shell runs with; programs are looked up in the directories it names. */
export const PINNED_PATH = "/usr/bin:/bin";

/** Programs that only read what their path arguments name. */
export const READ_ONLY_PROGRAMS: readonly string[] = ["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false"];

// Shell keywords and builtins that change shell state, assign variables (PATH included) or run other code: not simple commands we can check.
const REFUSED_FIRST_WORDS: ReadonlySet<string> = new Set([
  "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "select", "function", "time", "coproc",
  "cd", "pushd", "popd", "source", ".", "export", "unset", "alias", "unalias", "set", "shopt", "declare", "local", "readonly", "typeset",
  "let", "umask", "hash", "builtin", "command", "type", "trap", "wait", "read", "mapfile", "readarray", "enable", "bind", "complete",
  "printf", "getopts", "shift", "fc", "history", "ulimit", "kill", "jobs", "times",
]);

type Failure = { error: string };

const isBlank = (c: string): boolean => c === " " || c === "\t";
// Characters after which a word (or a file-descriptor duplication) ends.
const isDelimiter = (c: string | undefined): boolean => c === undefined || isBlank(c) || c === "\n" || c === ";" || c === "|" || c === "&";

/**
 * Parse a command line into simple commands joined by `|`, `&&`, `||`, `;` or newlines.
 * Anything outside the accepted subset is an error: expansions, substitutions, globs,
 * grouping, background jobs, here-documents, environment assignments, shell state builtins.
 */
export function parseBash(command: string): { commands: SimpleCommand[] } | Failure {
  const commands: SimpleCommand[] = [];
  let argv: string[] = [];
  let redirects: Redirect[] = [];
  let pending: Redirect["op"] | undefined;
  let word = "";
  let started = false; // a word is open (possibly empty, from quotes)
  let quoted = false; // part of the open word was quoted or escaped
  let lastSep: string | undefined;
  const fail = (error: string): Failure => ({ error });

  const endWord = (): Failure | undefined => {
    if (!started) {
      return undefined;
    }
    const w = word;
    word = "";
    started = false;
    quoted = false;
    if (pending !== undefined) {
      if (w === "") {
        return fail("empty redirect target");
      }
      redirects.push({ op: pending, target: w });
      pending = undefined;
    } else {
      if (argv.length === 0 && (w === "" || w.includes("=") || REFUSED_FIRST_WORDS.has(w))) {
        return fail("unsupported command word");
      }
      argv.push(w);
    }
    return undefined;
  };
  const endCommand = (sep: string): Failure | undefined => {
    const e = endWord();
    if (e) {
      return e;
    }
    if (pending !== undefined) {
      return fail("redirect without a target");
    }
    if (argv.length === 0) {
      if (redirects.length === 0 && sep === "\n") {
        return undefined; // a blank line
      }
      return fail("empty command");
    }
    commands.push({ argv, redirects });
    argv = [];
    redirects = [];
    lastSep = sep;
    return undefined;
  };
  /** Close the open word, then require that no redirect is still waiting for its target. */
  const beginRedirect = (): Failure | undefined => {
    const e = endWord();
    if (e) {
      return e;
    }
    return pending !== undefined ? fail("redirect without a target") : undefined;
  };
  /** True when the open word is an unquoted run of digits (a possible file descriptor). */
  const fdWord = (): boolean => started && !quoted && /^[0-9]+$/.test(word);
  const takeFd = (): string => {
    const fd = word;
    word = "";
    started = false;
    return fd;
  };

  const n = command.length;
  let i = 0;
  while (i < n) {
    const c = command[i] as string;
    const next = command[i + 1];
    if (c === "\0") {
      return fail("NUL in command");
    }
    if (c === "'") {
      const close = command.indexOf("'", i + 1);
      if (close < 0) {
        return fail("unterminated quote");
      }
      word += command.slice(i + 1, close);
      started = true;
      quoted = true;
      i = close + 1;
      continue;
    }
    if (c === '"') {
      started = true;
      quoted = true;
      i++;
      for (;;) {
        if (i >= n) {
          return fail("unterminated quote");
        }
        const d = command[i] as string;
        if (d === '"') {
          i++;
          break;
        }
        if (d === "$" || d === "`" || d === "\0") {
          return fail("expansion in double quotes");
        }
        if (d === "\\") {
          const e = command[i + 1];
          if (e === undefined || e === "\n" || e === "$" || e === "`" || e === "\0") {
            return fail("unsupported escape");
          }
          word += e === '"' || e === "\\" ? e : d + e;
          i += 2;
          continue;
        }
        word += d;
        i++;
      }
      continue;
    }
    if (c === "\\") {
      if (next === undefined || next === "\n" || next === "\0") {
        return fail("unsupported escape");
      }
      word += next;
      started = true;
      quoted = true;
      i += 2;
      continue;
    }
    if (isBlank(c)) {
      const e = endWord();
      if (e) {
        return e;
      }
      i++;
      continue;
    }
    if (c === "\n" || c === ";") {
      const e = endCommand(c);
      if (e) {
        return e;
      }
      i++;
      continue;
    }
    if (c === "|") {
      if (next === "&") {
        return fail("unsupported operator");
      }
      const op = next === "|" ? "||" : "|";
      const e = endCommand(op);
      if (e) {
        return e;
      }
      i += op.length;
      continue;
    }
    if (c === "&") {
      if (next === "&") {
        const e = endCommand("&&");
        if (e) {
          return e;
        }
        i += 2;
        continue;
      }
      return fail("background jobs are not supported");
    }
    if (c === "<") {
      if (next === "(" || next === "<" || next === "&" || next === ">") {
        return fail("unsupported redirect");
      }
      if (fdWord() && takeFd() !== "0") {
        return fail("unsupported file descriptor");
      }
      const e = beginRedirect();
      if (e) {
        return e;
      }
      pending = "<";
      i++;
      continue;
    }
    if (c === ">") {
      if (next === "(" || next === "|") {
        return fail("unsupported redirect");
      }
      if (next === "&") {
        // fd duplication: only >&1 and >&2, with no target
        const fd = command[i + 2];
        if ((fd !== "1" && fd !== "2") || !isDelimiter(command[i + 3])) {
          return fail("unsupported redirect");
        }
        if (fdWord()) {
          const from = takeFd();
          if (from !== "1" && from !== "2") {
            return fail("unsupported file descriptor");
          }
        }
        const e = beginRedirect();
        if (e) {
          return e;
        }
        i += 3;
        continue;
      }
      const append = next === ">";
      let op: Redirect["op"] = append ? ">>" : ">";
      if (fdWord()) {
        const fd = takeFd();
        if (fd === "2") {
          op = append ? "2>>" : "2>";
        } else if (fd !== "1") {
          return fail("unsupported file descriptor");
        }
      }
      const e = beginRedirect();
      if (e) {
        return e;
      }
      pending = op;
      i += append ? 2 : 1;
      continue;
    }
    if (c === "$" || c === "`" || c === "(" || c === ")" || c === "{" || c === "}" || c === "*" || c === "?" || c === "[" || c === "!") {
      return fail(`unsupported character ${c}`);
    }
    if (c === "~" || (!started && c === "#")) {
      return fail(`unsupported character ${c}`);
    }
    word += c;
    started = true;
    i++;
  }
  const e = endCommand("\n");
  if (e) {
    return e;
  }
  if (commands.length === 0 || lastSep === "&&" || lastSep === "||" || lastSep === "|") {
    return fail("empty command");
  }
  return { commands };
}

/** True when `p` exists, is a regular file (following symlinks) and is executable. */
function isExecutableFile(p: string): boolean {
  try {
    if (!statSync(p).isFile()) {
      return false;
    }
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function existsHere(cwd: string, arg: string): boolean {
  try {
    lstatSync(resolve(cwd, arg));
    return true;
  } catch {
    return false;
  }
}

// Read-only programs that can read below the working folder without being told: ls, and grep whatever its flags are spelled like.
const WALKERS: readonly string[] = ["ls", "grep"];

const hasDotDot = (arg: string): boolean => arg.split("/").includes("..");

/** Resolve one program name (argv[0]) to how the policy sees it, adding an exec path for a pathed program. */
function resolveProgram(name: string, ctx: PathContext & { pathDirs: readonly string[] }, paths: ResolvedPath[]): ResolvedProgram {
  if (name.includes("/")) {
    let real: string | undefined;
    try {
      real = basename(canonical(resolve(ctx.cwd, name)));
    } catch {
      real = undefined;
    }
    if (isNeverProgram(basename(name)) || (real !== undefined && isNeverProgram(real))) {
      return { name, via: "never" };
    }
    if (hasDotDot(name)) {
      paths.push({ need: "exec", at: "uncheckable" });
      return { name, via: "uncheckable" };
    }
    const p = resolvePathArg(name, "exec", ctx);
    paths.push(p);
    return { name, via: p.at === "uncheckable" ? "uncheckable" : "folder" };
  }
  if (isNeverProgram(name)) {
    return { name, via: "never" };
  }
  if (!ctx.rules.programs.includes(name)) {
    return { name, via: "missing" };
  }
  const found = ctx.pathDirs.map((d) => join(d, name)).find(isExecutableFile);
  if (found === undefined) {
    return { name, via: "missing" };
  }
  try {
    // an allowed name that is really a link to a program runner is that runner
    if (isNeverProgram(basename(realpathSync(found)))) {
      return { name, via: "never" };
    }
  } catch {
    return { name, via: "missing" };
  }
  return { name, via: "list" };
}

/**
 * Programs and paths a `bash` command would use. Read-only programs treat an operand
 * as a path when it has a "/", starts with "." or "~", or exists in the working folder;
 * any other program treats every operand as a path it may write. Options end at the
 * first operand or at "--" (BSD getopt), so everything after is an operand, "-x" and "-"
 * included. Every path also covers what lies below it. A path with a ".." component is
 * uncheckable (the shell follows symlinks before "..").
 *
 * The working folder is always a read. When any command is ls, grep, a program not in
 * READ_ONLY_PROGRAMS or a pathed program, it is walked too, whatever the flags say: these
 * may read or write below it without naming a path. Every walked root (named operands,
 * redirect targets, the working folder) is "refused" when a refused entry lies below it,
 * gets each nested folder rule as an extra path, and is "uncheckable" when a symlink below
 * it leads (canonically) out of it, a folder below cannot be read, or it holds more than
 * `walkLimit` (default WALK_LIMIT) entries: grep -R, ls -L and cp -L follow links. Links
 * that stay inside the root are fine. The check is conservative, not a guarantee.
 *
 * A command list in which any command but the last writes is refused whole as
 * parse "error" (so UNCHECKABLE): an earlier write can change what later paths mean.
 * A redirect to exactly /dev/null records no path and does not count as a write.
 */
export function resolveBash(command: string, ctx: PathContext & { pathDirs: readonly string[]; walkLimit?: number }): Resolved {
  const refusal: Resolved = { paths: [], programs: [], parse: "error", readOnly: false };
  const parsed = parseBash(command);
  if ("error" in parsed) {
    return refusal;
  }
  const isNull = (target: string): boolean => target === "/dev/null";
  const writes = (cmd: SimpleCommand): boolean =>
    !READ_ONLY_PROGRAMS.includes(cmd.argv[0] as string) || cmd.redirects.some((r) => r.op !== "<" && !isNull(r.target));
  if (parsed.commands.slice(0, -1).some(writes)) {
    return refusal;
  }
  // bash's walkers can follow symlinks (grep -R, ls -L, cp -L): every walked root has its links checked.
  const subtree = { links: { limit: ctx.walkLimit ?? WALK_LIMIT } };
  const cwdPath = resolvePathArg(".", "read", ctx);
  const paths: ResolvedPath[] = [cwdPath];
  const programs: ResolvedProgram[] = [];
  let readOnly = true;
  let walks = false;
  const addPath = (arg: string, need: Need): void => {
    if (hasDotDot(arg)) {
      paths.push({ need, at: "uncheckable" });
      return;
    }
    const p = resolvePathArg(arg, need, ctx);
    paths.push(...(p.at === "uncheckable" ? [p] : withSubtree(resolve(ctx.cwd, arg), p, ctx, subtree)));
  };
  const looksLikePath = (v: string): boolean => v.includes("/") || v.startsWith(".") || v.startsWith("~") || existsHere(ctx.cwd, v);
  /** The value attached to an option: unjudgeable for a program that may write, a read path when it looks like one otherwise. */
  const optionValue = (v: string, ro: boolean, need: Need): void => {
    if (!ro) {
      paths.push({ need, at: "uncheckable" });
    } else if (looksLikePath(v)) {
      addPath(v, "read");
    }
  };
  for (const cmd of parsed.commands) {
    const name = cmd.argv[0] as string;
    const program = resolveProgram(name, ctx, paths);
    if (!programs.some((p) => p.name === program.name && p.via === program.via)) {
      programs.push(program);
    }
    const roProgram = READ_ONLY_PROGRAMS.includes(name);
    if (writes(cmd)) {
      readOnly = false;
    }
    for (const r of cmd.redirects) {
      if (!isNull(r.target)) {
        addPath(r.target, r.op === "<" ? "read" : "write");
      }
    }
    const need: Need = roProgram ? "read" : "write";
    let optionsEnded = false;
    for (const arg of cmd.argv.slice(1)) {
      if (!optionsEnded && arg === "--") {
        optionsEnded = true;
        continue;
      }
      if (arg.startsWith("-") && arg !== "-" && arg !== "--") {
        // Some tools permute arguments, and an option's separate argument can end option parsing early,
        // so any dashed token may carry an attached value: judge it wherever it stands.
        if (arg.startsWith("--")) {
          const eq = arg.indexOf("=");
          if (eq > 0) {
            optionValue(arg.slice(eq + 1), roProgram, need);
          }
        } else if (roProgram) {
          for (let k = 2; k < arg.length; k++) {
            optionValue(arg.slice(k), true, need);
          }
        } else if (arg.length > 2) {
          paths.push({ need, at: "uncheckable" });
        }
        if (!optionsEnded) {
          continue;
        }
      } else {
        optionsEnded = true;
      }
      if (!roProgram || looksLikePath(arg)) {
        addPath(arg, need);
      }
    }
    // Unconditionally, whatever else was named or however flags are spelled: these may walk the working folder.
    if (!roProgram || WALKERS.includes(name)) {
      walks = true;
    }
  }
  if (walks) {
    const sub = withSubtree(ctx.cwd, cwdPath, ctx, subtree);
    paths.push(...(sub[0] === cwdPath ? sub.slice(1) : sub));
  }
  return { paths, programs, parse: "ok", readOnly };
}
