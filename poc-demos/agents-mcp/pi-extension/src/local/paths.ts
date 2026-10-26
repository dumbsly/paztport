// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Disk-aware resolution of the paths pi's file tools are about to touch. When in
// doubt the answer is "uncheckable" or "outside", never a guess.

import { accessSync, constants, lstatSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import type { LocalRules, Need, Resolved, ResolvedPath } from "@paztport/core";

export type PathContext = { cwd: string; workspace: string; rules: LocalRules; refused: readonly string[] };

// pi's UNICODE_SPACES set (utils/paths.ts) plus U+FEFF.
const UNICODE_SPACES = /[  -   　﻿]/;

/** True when pi's normalizePath would rewrite `p`: leading "@", a Unicode space, "~" or "~/", or "file://". */
export function piRewrites(p: string): boolean {
  return p.startsWith("@") || UNICODE_SPACES.test(p) || p === "~" || p.startsWith("~/") || p.startsWith("file://");
}

/**
 * The real path of `abs`: realpath (native, canonical case) of the nearest existing
 * ancestor joined with the rest. Throws when an entry exists but cannot be resolved
 * (a dangling symlink, a loop, no permission), because its target is unknown.
 */
export function canonical(abs: string): string {
  let head = resolve(abs);
  const rest: string[] = [];
  for (;;) {
    try {
      const real = realpathSync.native(head);
      return rest.length === 0 ? real : join(real, ...rest);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        throw e;
      }
      let exists = true;
      try {
        lstatSync(head);
      } catch {
        exists = false;
      }
      if (exists) {
        throw e;
      }
      const parent = dirname(head);
      if (parent === head) {
        throw e;
      }
      rest.unshift(head.slice(parent.length === 1 ? 1 : parent.length + 1));
      head = parent;
    }
  }
}

/** Component-wise containment: equal to `base`, or below it. */
function isUnder(p: string, base: string): boolean {
  if (p === base) {
    return true;
  }
  return p.startsWith(base.endsWith(sep) ? base : base + sep);
}

/** Spelling-insensitive form: NFC always (APFS ignores normalisation form on any volume), lower case when the volume ignores case. */
const folder = (ci: boolean) => (s: string): string => (ci ? s.normalize("NFC").toLowerCase() : s.normalize("NFC"));

const caseCache = new Map<string, boolean>();

/**
 * Whether the volume holding `canonicalPath` ignores case, found by statting a
 * case-flipped spelling of its nearest existing component. Unknown counts as
 * case-insensitive, which only ever makes the checks stricter.
 */
function caseInsensitive(canonicalPath: string): boolean {
  const cached = caseCache.get(canonicalPath);
  if (cached !== undefined) {
    return cached;
  }
  let result = true;
  let p = canonicalPath;
  for (;;) {
    const parent = dirname(p);
    if (parent === p) {
      break;
    }
    const name = p.slice(parent.length === 1 ? 1 : parent.length + 1);
    const flipped = [...name].map((ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase())).join("");
    if (flipped !== name) {
      try {
        const a = statSync(p);
        let b;
        try {
          b = statSync(join(parent, flipped));
        } catch {
          result = false;
          break;
        }
        result = a.ino === b.ino && a.dev === b.dev;
      } catch {
        result = true;
      }
      break;
    }
    p = parent;
  }
  caseCache.set(canonicalPath, result);
  return result;
}

type RuleLoc = { loc: string; at: string };

/**
 * Where each folder rule really lies on disk (canonical, so a rule spelled through an
 * in-workspace symlink governs the real folder), with the `at` spelling that names it.
 * Throws when a rule's location cannot be resolved: nothing is then judged.
 */
function ruleLocations(ctx: PathContext, ws: string): RuleLoc[] {
  const out: RuleLoc[] = [];
  for (const rule of ctx.rules.folders) {
    const spelled = posix.normalize(rule.path).replace(/(.)\/$/, "$1");
    if (isAbsolute(rule.path)) {
      out.push({ loc: canonical(spelled), at: spelled });
    } else {
      const loc = spelled === "." ? ws : canonical(join(ws, spelled));
      // A relative rule that really lies outside the workspace (a symlink out) matches nothing.
      if (isUnder(loc, ws)) {
        out.push({ loc, at: spelled });
      }
    }
  }
  return out;
}

/** Resolve one path argument the way pi's file tools would, to a workspace-relative or absolute `at`. */
export function resolvePathArg(arg: string, need: Need, ctx: PathContext): ResolvedPath {
  const uncheckable: ResolvedPath = { need, at: "uncheckable" };
  if (arg.includes("\0") || piRewrites(arg)) {
    return uncheckable;
  }
  let c: string;
  let ws: string;
  let refused: string[];
  let locs: RuleLoc[];
  try {
    c = canonical(resolve(ctx.cwd, arg));
    ws = canonical(ctx.workspace);
    refused = ctx.refused.map((r) => canonical(r));
    locs = ruleLocations(ctx, ws);
  } catch {
    return uncheckable;
  }
  const fold = folder(caseInsensitive(ws));
  if (refused.some((r) => isUnder(c, r) || isUnder(fold(c), fold(r)))) {
    return { need, at: "refused" };
  }
  // A spelling that reaches a folder rule only after folding cannot be judged.
  if (locs.some((l) => !isUnder(c, l.loc) && isUnder(fold(c), fold(l.loc)))) {
    return uncheckable;
  }
  let best: RuleLoc | undefined;
  for (const l of locs) {
    if (isUnder(c, l.loc) && (best === undefined || l.loc.length > best.loc.length)) {
      best = l;
    }
  }
  if (best !== undefined && locs.filter((l) => l.loc === best.loc).length > 1) {
    // Two rules name the same real folder: which one governs would depend on their order.
    return uncheckable;
  }
  if (best !== undefined) {
    // Record `at` in the winning rule's own spelling so folderRuleFor finds it from the recorded value alone.
    const tail = relative(best.loc, c).split(sep).filter((x) => x !== "").join("/");
    return { need, at: tail === "" ? best.at : posix.join(best.at, tail) };
  }
  if (isUnder(c, ws)) {
    const rel = relative(ws, c);
    return { need, at: rel === "" ? "." : rel.split(sep).join("/") };
  }
  return { need, at: "outside" };
}

/** How many entries a walk for links may visit before the root counts as uncheckable. */
export const WALK_LIMIT = 20_000;

/**
 * Whether every symlink below the canonical directory `root` points (canonically) inside it.
 * Walks with lstat and never follows a link. False when a link leads out or cannot be resolved,
 * a folder cannot be read, or there are more than `limit` entries.
 */
function linksStayInside(root: string, limit: number): boolean {
  let seen = 0;
  const pending: string[] = [];
  try {
    if (lstatSync(root).isDirectory()) {
      pending.push(root);
    }
  } catch (e) {
    // nothing there yet (a path about to be written): nothing to walk
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ENOENT" || code === "ENOTDIR";
  }
  for (let dir = pending.pop(); dir !== undefined; dir = pending.pop()) {
    try {
      for (const name of readdirSync(dir)) {
        if (++seen > limit) {
          return false;
        }
        const entry = join(dir, name);
        const st = lstatSync(entry);
        if (st.isSymbolicLink()) {
          if (!isUnder(canonical(entry), root)) {
            return false;
          }
        } else if (st.isDirectory()) {
          pending.push(entry);
        }
      }
    } catch {
      return false;
    }
  }
  return true;
}

/** `links`: the walker may follow symlinks (bash's grep -R, ls -L, cp -L), so check every link below the root. */
export type SubtreeOptions = { links?: { limit: number } };

/**
 * `base` (the resolution of `abs`) widened to everything below `abs`: a refused entry below
 * makes it "refused", a folder rule only reachable after folding makes it "uncheckable", and
 * every nested folder rule is added as an extra path with the same need. With `links`, a
 * symlink below that leads out of the root, an unreadable folder, or more entries than the
 * limit also make it "uncheckable" (a base already "outside" or "refused" is not walked).
 */
export function withSubtree(abs: string, base: ResolvedPath, ctx: PathContext, opts: SubtreeOptions = {}): ResolvedPath[] {
  const need = base.need;
  try {
    const cs = canonical(abs);
    const ws = canonical(ctx.workspace);
    const fold = folder(caseInsensitive(ws));
    const locs = ruleLocations(ctx, ws);
    if (ctx.refused.some((r) => isUnder(canonical(r), cs) || isUnder(fold(canonical(r)), fold(cs)))) {
      return [{ need, at: "refused" }];
    }
    if (locs.some((l) => !isUnder(l.loc, cs) && isUnder(fold(l.loc), fold(cs)))) {
      // a folder rule lies below the root only after folding: its access and label cannot be judged
      return [{ need, at: "uncheckable" }];
    }
    if (opts.links !== undefined && base.at !== "outside" && base.at !== "refused" && !linksStayInside(cs, opts.links.limit)) {
      return [{ need, at: "uncheckable" }];
    }
    const extra: ResolvedPath[] = [];
    for (const l of locs) {
      if (l.loc !== cs && isUnder(l.loc, cs)) {
        extra.push({ need, at: l.at });
      }
    }
    return [base, ...extra];
  } catch {
    return [{ need, at: "uncheckable" }];
  }
}

const READ_TOOLS: readonly string[] = ["read", "grep", "find", "ls"];

/** pi's read tool retries a missing path with these spellings (path-utils.ts, same order). */
function piReadVariants(p: string): string[] {
  const amPm = p.replace(/ (AM|PM)\./gi, "\u202F$1.");
  const nfd = p.normalize("NFD");
  const curly = p.replace(/'/g, "\u2019");
  const nfdCurly = nfd.replace(/'/g, "\u2019");
  return [amPm, nfd, curly, nfdCurly].filter((v) => v !== p);
}

function exists(p: string): boolean {
  try {
    accessSync(p, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/** Resolution for one of pi's file tools. `read`, `grep`, `find`, `ls` need read; `write`, `edit` need write. */
export function resolveFileTool(
  tool: "read" | "write" | "edit" | "grep" | "find" | "ls",
  input: Record<string, unknown>,
  ctx: PathContext,
): Resolved {
  const readOnly = READ_TOOLS.includes(tool);
  const need: Need = readOnly ? "read" : "write";
  const raw = input.path ?? ".";
  let extra: ResolvedPath[] = [];
  let path: ResolvedPath = typeof raw === "string" ? resolvePathArg(raw, need, ctx) : { need, at: "uncheckable" };
  const pattern = tool === "grep" ? input.glob : tool === "find" ? input.pattern : undefined;
  if (typeof pattern === "string" && (pattern.includes("..") || pattern.startsWith("/"))) {
    path = { need, at: "uncheckable" };
  }
  if (typeof raw === "string" && path.at !== "uncheckable") {
    const abs = resolve(ctx.cwd, raw);
    if (tool === "read" && !exists(abs) && piReadVariants(abs).some(exists)) {
      // pi would open a different file than the one named; do not guess which.
      path = { need, at: "uncheckable" };
    } else if (tool === "grep" || tool === "find" || tool === "ls") {
      // These walk everything below the root: refused entries and nested folders count too.
      [path, ...extra] = withSubtree(abs, path, ctx);
    }
  }
  return { paths: [path, ...extra], programs: [], parse: "ok", readOnly };
}
