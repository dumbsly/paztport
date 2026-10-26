// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The pure verdict for a local tool call. No filesystem access here: the same
// rule is reused by offline verification over a recorded resolution. It imports
// only node:path's pure posix helpers, never node:fs.

import { posix } from "node:path";
import type { FolderRule, InfluenceClass, LocalRules } from "@paztport/core";

export type Need = "read" | "write" | "exec";

/**
 * `at` is a POSIX path relative to the workspace ("." for the root), the absolute
 * path when it lies inside an absolute folder rule, or one of the markers
 * "outside", "refused", "uncheckable". A workspace entry literally named like a
 * marker is therefore treated as the marker (it is refused, never allowed).
 */
export type ResolvedPath = { need: Need; at: string };
export type ResolvedProgram = { name: string; via: "list" | "folder" | "never" | "missing" | "uncheckable" };
export type Resolved = { paths: ResolvedPath[]; programs: ResolvedProgram[]; parse: "ok" | "error"; readOnly: boolean };
export type LocalVerdict = "OK" | "PATH_NOT_ALLOWED" | "SCOPE_DENIED" | "UNCHECKABLE" | "INFLUENCE_DENIED";

const MARKERS: readonly string[] = ["outside", "refused", "uncheckable"];

/** Normalised form of a folder rule path: "." for the root, no "./" prefix, no trailing "/". */
function normalFolder(p: string): string {
  const n = posix.normalize(p);
  return n.length > 1 && n.endsWith("/") ? n.slice(0, -1) : n;
}

/** The longest folder rule whose path equals `at` or is a "/"-prefix of it; relative and absolute rules match in their own spaces. */
export function folderRuleFor(at: string, rules: LocalRules): FolderRule | undefined {
  if (MARKERS.includes(at) || at === "" || at.split("/").includes("..")) {
    return undefined;
  }
  const absolute = at.startsWith("/");
  const a = absolute ? posix.normalize(at) : at;
  let best: FolderRule | undefined;
  let bestLen = -1;
  for (const rule of rules.folders) {
    const f = normalFolder(rule.path);
    if (f.startsWith("/") !== absolute) {
      continue;
    }
    const match = f === "." || f === "/" || a === f || a.startsWith(`${f}/`);
    // The root "." counts as length 0, so any named folder beats it whatever the rule order.
    const len = f === "." ? 0 : f.length;
    if (match && len > bestLen) {
      best = rule;
      bestLen = len;
    }
  }
  return best;
}

/**
 * The first matching rule wins: route, then uncheckable, then scope, then influence. The influence rule is
 * decided on the session's classes plus `private` when the call itself reads a private-labelled folder, so a
 * single call that copies a private folder into a public one is decided as a read followed by a write would be.
 * The call's other read labels are not added: its own reads carry data, not instructions, and the model never
 * saw that content, so it can't have steered the call. Only private data moving matters there.
 */
export function decideLocal(d: {
  routeAllowed: boolean;
  resolved: Resolved;
  rules: LocalRules;
  classes: ReadonlySet<InfluenceClass>;
}): LocalVerdict {
  const { resolved, rules, classes } = d;
  if (!d.routeAllowed) {
    return "PATH_NOT_ALLOWED";
  }
  if (resolved.parse === "error" || resolved.paths.some((p) => p.at === "uncheckable") || resolved.programs.some((p) => p.via === "uncheckable")) {
    return "UNCHECKABLE";
  }
  const folders = resolved.paths.map((p) => ({ p, rule: folderRuleFor(p.at, rules) }));
  if (
    folders.some(({ p, rule }) => p.at === "outside" || p.at === "refused" || rule === undefined || !rule.access.includes(p.need)) ||
    resolved.programs.some((p) => p.via === "never" || p.via === "missing")
  ) {
    return "SCOPE_DENIED";
  }
  const all = new Set<InfluenceClass>(classes);
  if (readLabels(resolved, rules).includes("private")) {
    all.add("private");
  }
  if (all.has("private") && (all.has("third-party") || all.has("local-untrusted"))) {
    if (folders.some(({ p, rule }) => p.need === "write" && rule?.destination === "public")) {
      return "INFLUENCE_DENIED";
    }
  }
  return "OK";
}

/** The distinct label of the folder of every read path; an unlabelled folder (or none) reads as local-untrusted. */
export function readLabels(resolved: Resolved, rules: LocalRules): InfluenceClass[] {
  const out = new Set<InfluenceClass>();
  for (const p of resolved.paths) {
    if (p.need === "read") {
      out.add(folderRuleFor(p.at, rules)?.label ?? "local-untrusted");
    }
  }
  return [...out];
}
