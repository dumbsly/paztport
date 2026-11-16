// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0
//
// What the Markdown checks share: a file's headings, with the anchors GitHub gives them, and the link targets a
// file offers. Lines inside ``` or ~~~ fences are code, so a `# comment` there is not a heading.

/**
 * The headings outside fenced code blocks, in order, with their 1-based line numbers. Anchors are GitHub's: lower
 * case, punctuation dropped, spaces to hyphens, a repeat numbered -1, -2 and on.
 */
export function headings(text) {
  const seen = new Map();
  const out = [];
  let fenced = false;
  text.split("\n").forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    const m = !fenced && /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) return;
    const base = m[2]
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s/g, "-");
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.push({ level: m[1].length, anchor: n === 0 ? base : `${base}-${n}`, line: i + 1 });
  });
  return out;
}

/** The targets a `#fragment` may name: the heading anchors, and `<a name="…">` or `<a id="…">`. */
export function anchors(text) {
  const out = new Set(headings(text).map((h) => h.anchor));
  for (const m of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) out.add(m[1]);
  return out;
}
