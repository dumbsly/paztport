// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Disk-aware resolution of the paths pi's file tools are about to touch. When in
// doubt the answer is "uncheckable" or "outside", never a guess.

import { lstatSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import type { LocalRules } from "@paztport/path-attest";
import type { Need, Resolved, ResolvedPath } from "./decide.ts";

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

/** Resolve one path argument the way pi's file tools would, to a workspace-relative or absolute `at`. */
export function resolvePathArg(arg: string, need: Need, ctx: PathContext): ResolvedPath {
  const uncheckable: ResolvedPath = { need, at: "uncheckable" };
  if (arg.includes("\0") || piRewrites(arg)) {
    return uncheckable;
  }
  let c: string;
  let ws: string;
  let refused: string[];
  try {
    c = canonical(resolve(ctx.cwd, arg));
    ws = canonical(ctx.workspace);
    refused = ctx.refused.map((r) => canonical(r));
  } catch {
    return uncheckable;
  }
  if (refused.some((r) => isUnder(c, r))) {
    return { need, at: "refused" };
  }
  if (isUnder(c, ws)) {
    const rel = relative(ws, c);
    return { need, at: rel === "" ? "." : rel.split(sep).join("/") };
  }
  let best: { len: number; at: string } | undefined;
  for (const rule of ctx.rules.folders) {
    if (!isAbsolute(rule.path)) {
      continue;
    }
    const spelled = posix.normalize(rule.path).replace(/(.)\/$/, "$1");
    let real: string;
    try {
      real = canonical(spelled);
    } catch {
      continue;
    }
    if (isUnder(c, real) && (best === undefined || real.length > best.len)) {
      // Keep the rule's own spelling so the verdict can match the folder rule.
      const tail = c.slice(real.length).split(sep).filter((s) => s !== "").join("/");
      best = { len: real.length, at: tail === "" ? spelled : posix.join(spelled, tail) };
    }
  }
  return { need, at: best?.at ?? "outside" };
}

const READ_TOOLS: readonly string[] = ["read", "grep", "find", "ls"];

/** Resolution for one of pi's file tools. `read`, `grep`, `find`, `ls` need read; `write`, `edit` need write. */
export function resolveFileTool(
  tool: "read" | "write" | "edit" | "grep" | "find" | "ls",
  input: Record<string, unknown>,
  ctx: PathContext,
): Resolved {
  const readOnly = READ_TOOLS.includes(tool);
  const need: Need = readOnly ? "read" : "write";
  const raw = input.path ?? ".";
  let path: ResolvedPath = typeof raw === "string" ? resolvePathArg(raw, need, ctx) : { need, at: "uncheckable" };
  const pattern = tool === "grep" ? input.glob : tool === "find" ? input.pattern : undefined;
  if (typeof pattern === "string" && (pattern.includes("..") || pattern.startsWith("/"))) {
    path = { need, at: "uncheckable" };
  }
  return { paths: [path], programs: [], parse: "ok", readOnly };
}
