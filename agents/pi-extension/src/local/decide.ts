// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The pure verdict for a local tool call. No filesystem access here: the same
// rule is reused by offline verification over a recorded resolution.

import { posix } from "node:path";
import type { FolderRule, InfluenceClass, LocalRules } from "@paztport/path-attest";

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
    if (match && f.length > bestLen) {
      best = rule;
      bestLen = f.length;
    }
  }
  return best;
}

/** The first matching rule wins: route, then uncheckable, then scope, then influence. */
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
  if (classes.has("private") && (classes.has("third-party") || classes.has("local-untrusted"))) {
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
