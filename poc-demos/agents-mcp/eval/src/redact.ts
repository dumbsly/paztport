// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, realpathSync, writeFileSync } from "node:fs";

/** An absolute path and what replaces it in files meant for publishing. */
export type Redaction = { path: string; placeholder: string };

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Replaces each path with its placeholder, longest path first, so a run folder inside the agents-mcp folder
 * inside the home folder becomes `<run-dir>`, not `<home>/...`. A path matches only where it ends a name
 * (`/Users/ann` does not match inside `/Users/anna`). The JSON-escaped form of a path (backslashes doubled)
 * is replaced too. Empty paths and "/" are ignored.
 */
export function redactPaths(text: string, redactions: readonly Redaction[]): string {
  const forms: Redaction[] = [];
  for (const r of redactions) {
    if (r.path.length <= 1) continue;
    forms.push(r);
    const escaped = JSON.stringify(r.path).slice(1, -1);
    if (escaped !== r.path) forms.push({ path: escaped, placeholder: r.placeholder });
  }
  forms.sort((a, b) => b.path.length - a.path.length);
  let out = text;
  for (const f of forms) out = out.replace(new RegExp(`${escapeRegExp(f.path)}(?![A-Za-z0-9._-])`, "g"), () => f.placeholder);
  return out;
}

/** The path as given and, when it differs (a symlinked temp folder, for example), as the system resolves it. */
export function withRealPath(r: Redaction): Redaction[] {
  try {
    const real = realpathSync(r.path);
    return real !== r.path ? [r, { path: real, placeholder: r.placeholder }] : [r];
  } catch {
    return [r];
  }
}

/** Rewrites a file with its paths redacted. A file that is missing or can't be rewritten is left as it is. */
export function redactFile(file: string, redactions: readonly Redaction[]): void {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return;
  }
  const next = redactPaths(text, redactions);
  if (next !== text) writeFileSync(file, next);
}
