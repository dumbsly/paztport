// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0
//
// Fails if a Markdown link points at nothing: a relative path that is not in the repository (tracked, or new
// and not ignored), a `#heading` that the target file does not have, or a path that leaves the repository.
// http(s) and mailto links are not followed. Usage: node check-links.mjs [repo root]
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";

const root = resolve(process.argv[2] ?? join(import.meta.dirname, "../.."));

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter((f) => f !== "");
const known = new Set(files);
for (const f of files) for (let d = posix.dirname(f); d !== "."; d = posix.dirname(d)) known.add(d);

/** The text outside fenced code blocks, with inline code spans blanked so their brackets are not read as links. */
function prose(text) {
  let fenced = false;
  return text
    .split("\n")
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) {
        fenced = !fenced;
        return "";
      }
      return fenced ? "" : line.replace(/`+[^`]*`+/g, (m) => " ".repeat(m.length));
    })
    .join("\n");
}

/** GitHub's heading anchors: lower case, punctuation dropped, spaces to hyphens, repeats numbered. */
function anchors(text) {
  const seen = new Map();
  const out = new Set();
  let fenced = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    const m = !fenced && /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    const base = m[1]
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s/g, "-");
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  }
  for (const m of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) out.add(m[1]);
  return out;
}

const anchorCache = new Map();
const anchorsOf = (file) => {
  if (!anchorCache.has(file)) anchorCache.set(file, anchors(readFileSync(join(root, file), "utf8")));
  return anchorCache.get(file);
};

const problems = [];
for (const file of files.filter((f) => f.endsWith(".md"))) {
  const text = prose(readFileSync(join(root, file), "utf8"));
  const targets = [
    ...[...text.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)].map((m) => [m[1], m.index]),
    ...[...text.matchAll(/^\s{0,3}\[[^\]]+\]:\s+<?(\S+?)>?(?:\s|$)/gm)].map((m) => [m[1], m.index]),
  ];
  for (const [target, index] of targets) {
    const where = `${file}:${text.slice(0, index).split("\n").length}`;
    if (/^(https?|mailto):/i.test(target)) continue;
    if (/^[a-z][a-z0-9+.-]*:/i.test(target)) {
      problems.push(`${where}: ${target} (only http(s) and mailto links may leave the repository)`);
      continue;
    }
    const hash = target.indexOf("#");
    const path = decodeURIComponent(hash < 0 ? target : target.slice(0, hash));
    const fragment = hash < 0 ? "" : decodeURIComponent(target.slice(hash + 1));
    const abs = path === "" ? join(root, file) : path.startsWith("/") ? join(root, path) : resolve(root, dirname(file), path);
    const rel = relative(root, abs).split("\\").join("/");
    if (rel.startsWith("..")) {
      problems.push(`${where}: ${target} (leaves the repository)`);
      continue;
    }
    const inRepo = rel === "" ? "." : rel.replace(/\/$/, "");
    if (inRepo !== "." && !known.has(inRepo)) {
      problems.push(`${where}: ${target} (no such file in the repository)`);
      continue;
    }
    if (fragment !== "" && inRepo.endsWith(".md") && !anchorsOf(inRepo).has(fragment)) {
      problems.push(`${where}: ${target} (no heading #${fragment} in ${inRepo})`);
    }
  }
}

if (problems.length > 0) {
  for (const p of problems) console.error(p);
  console.error(`check-links: ${problems.length} broken link(s)`);
  process.exit(1);
}
