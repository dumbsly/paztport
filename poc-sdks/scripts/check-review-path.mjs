// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0
//
// Fails if a line count in the review path is not the count of what its row links to. Every table in the file has
// the header | Read | What to look for | Lines |; each row's first cell holds one link to a repository file, with an
// optional #anchor naming a heading in a Markdown file, and its last cell the count, digits with optional thousands
// commas; the table ends with | **Total** | | <n> |, the sum of the counts above it. A whole file's count is its
// lines as an editor numbers them, the last counted though it has no newline. A section's runs from its heading to
// the line before the next heading of the same or a higher level, or to the end of the file; a line inside a fenced
// code block is not a heading. A link that names a missing file, a directory or an anchor the file lacks fails, as
// does one that leaves the repository, a row with a link and no count or a count and no link, and a count cell
// holding anything else. Links resolve from the file's directory, as check-links.mjs resolves them; a file outside
// the repository (a copy under test) is read as if it stood at docs/review-path.md.
// Usage: node check-review-path.mjs [repo root] [file, default docs/review-path.md]
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { headings } from "./markdown.mjs";

const DEFAULT = "docs/review-path.md";
const root = resolve(process.argv[2] ?? join(import.meta.dirname, "../.."));
const file = resolve(root, process.argv[3] ?? DEFAULT);
const inside = !relative(root, file).startsWith("..");
const shown = inside ? relative(root, file).split("\\").join("/") : file;
const base = inside ? dirname(file) : join(root, dirname(DEFAULT));

if (!existsSync(file) || !statSync(file).isFile()) {
  console.error(`check-review-path: no file ${shown} under ${root}`);
  process.exit(1);
}

// The repository's files as check-links.mjs sees them: tracked, or new and not ignored, and present on disk.
const files = new Set(
  execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter((f) => f !== "" && existsSync(join(root, f))),
);
const dirs = new Set();
for (const f of files) for (let d = posix.dirname(f); d !== "."; d = posix.dirname(d)) dirs.add(d);

/** Lines as an editor numbers them: a final line without a newline counts, the empty one after a newline does not. */
const lineCount = (text) => (text === "" ? 0 : text.split("\n").length - (text.endsWith("\n") ? 1 : 0));

/** The lines from the heading the anchor names to the line before the next heading of its level or higher. */
function sectionCount(text, anchor) {
  const all = headings(text);
  const at = all.findIndex((h) => h.anchor === anchor);
  if (at < 0) return undefined;
  const next = all.slice(at + 1).find((h) => h.level <= all[at].level);
  return (next ? next.line - 1 : lineCount(text)) - all[at].line + 1;
}

/** The count a link's target has, or the reason it has none. */
function count(target) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return { problem: "not a repository file" };
  const hash = target.indexOf("#");
  let path;
  let fragment;
  try {
    path = decodeURIComponent(hash < 0 ? target : target.slice(0, hash));
    fragment = hash < 0 ? "" : decodeURIComponent(target.slice(hash + 1));
  } catch {
    return { problem: "a malformed %-escape" };
  }
  const abs = path === "" ? file : path.startsWith("/") ? join(root, path) : resolve(base, path);
  const rel = relative(root, abs).split("\\").join("/");
  if (rel.startsWith("..")) return { problem: "leaves the repository" };
  const name = rel.replace(/\/$/, "");
  if (name === "" || dirs.has(name)) return { problem: "a directory, not a file" };
  if (!files.has(name)) return { problem: "no such file in the repository" };
  const text = readFileSync(abs, "utf8");
  if (fragment === "") return { lines: lineCount(text) };
  if (!name.endsWith(".md")) return { problem: `an anchor in ${name}, which is not Markdown` };
  const lines = sectionCount(text, fragment);
  return lines === undefined ? { problem: `no heading #${fragment} in ${name}` } : { lines };
}

/** A row's cells, split on the pipes that are not escaped, the outer pipes dropped. */
const cells = (line) =>
  line
    .trim()
    .replace(/^\|/, "")
    .replace(/(?<!\\)\|$/, "")
    .split(/(?<!\\)\|/)
    .map((c) => c.trim());

/** `n` with a comma between each group of three digits, as the counts are written. */
const grouped = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

const LINK = /\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const COUNT = /^(\d+|\d{1,3}(,\d{3})+)$/;
const HEADER = ["Read", "What to look for", "Lines"];

// The tables, outside fenced code blocks: runs of lines that start with a pipe, each line with its number.
const tables = [];
let fenced = false;
let current = null;
readFileSync(file, "utf8")
  .split("\n")
  .forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (!fenced && /^\s*\|/.test(line)) {
      if (current === null) tables.push((current = []));
      current.push({ line: i + 1, text: line });
    } else current = null;
  });

const problems = [];
let rows = 0;
if (tables.length === 0) problems.push(`${shown}: no tables`);
for (const table of tables) {
  const where = (row) => `${shown}:${row.line}`;
  const [header, rule, ...body] = table;
  if (cells(header.text).join("|") !== HEADER.join("|")) {
    problems.push(`${where(header)}: a table whose header is not | ${HEADER.join(" | ")} |`);
    continue;
  }
  if (rule === undefined || !cells(rule.text).every((c) => /^:?-+:?$/.test(c))) {
    problems.push(`${where(header)}: the header has no |---| line under it`);
    continue;
  }
  let sum = 0;
  // A row whose count does not read leaves the sum unknown, so the Total is then not compared with it.
  let summed = true;
  let total = null;
  for (const row of body) {
    if (total !== null) {
      problems.push(`${where(row)}: a row after the Total`);
      continue;
    }
    const c = cells(row.text);
    if (c.length !== 3) {
      problems.push(`${where(row)}: ${c.length} cells, not 3`);
      summed = false;
      continue;
    }
    const [read, middle, written] = c;
    const n = COUNT.test(written) ? Number(written.replaceAll(",", "")) : undefined;
    if (read === "**Total**") {
      total = { row, n, written, middle };
      continue;
    }
    if (n === undefined) summed = false;
    else sum += n;
    const links = [...read.matchAll(LINK)].map((m) => m[1]);
    if (links.length !== 1) {
      problems.push(`${where(row)}: ${read === "" ? "an empty first cell" : read} holds ${links.length} links, not 1`);
      continue;
    }
    const [target] = links;
    rows += 1;
    if (n === undefined) {
      const why = written === "" ? "has no count" : `has the count "${written}", not a number`;
      problems.push(`${where(row)}: ${target} ${why}`);
      continue;
    }
    const got = count(target);
    if (got.problem !== undefined) {
      problems.push(`${where(row)}: ${target} (${got.problem})`);
    } else if (got.lines !== n) {
      problems.push(`${where(row)}: ${target} has ${grouped(got.lines)} lines, written ${written}`);
    }
  }
  if (total === null) {
    problems.push(`${where(table.at(-1))}: the table has no | **Total** | | <n> | row`);
    continue;
  }
  if (total.middle !== "") problems.push(`${where(total.row)}: the Total row's middle cell is not empty`);
  if (total.n === undefined) {
    const why = total.written === "" ? "has no count" : `"${total.written}" is not a number`;
    problems.push(`${where(total.row)}: the Total ${why}`);
  } else if (summed && total.n !== sum) {
    problems.push(`${where(total.row)}: the rows above sum to ${grouped(sum)}, Total written ${total.written}`);
  }
}

if (problems.length > 0) {
  for (const p of problems) console.error(p);
  console.error(`check-review-path: ${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`check-review-path: ok, ${rows} rows in ${tables.length} tables`);
