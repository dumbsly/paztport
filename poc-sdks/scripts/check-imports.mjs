// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0
//
// Fails if a Java file has an import it does not need: one whose name is used neither in code nor in a doc comment
// reference, a repeat, one from java.lang, or one from the file's own package. A name is used where it stands
// unqualified in code (strings, character literals and comments left out), or where javadoc resolves it: the
// target of {@link}, {@linkplain}, {@value}, @see, @throws or @exception in a /** */ comment, and the parameter
// types in such a reference. An import of any other form (a wildcard, a module import) is not checked, so it fails
// too. Reads the repository's Java files (tracked, or new and not ignored). Usage: node check-imports.mjs [repo root]
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] ?? join(import.meta.dirname, "../.."));

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.java"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter((f) => f !== "");
if (files.length === 0) {
  console.error(`check-imports: no Java files at ${root}; is this the repository root?`);
  process.exit(1);
}

const SINGLE = /^[ \t]*import[ \t]+(static[ \t]+)?([\w$.]+)[ \t]*;[ \t]*$/;
const PACKAGE = /^[ \t]*package[ \t]+([\w.]+)[ \t]*;/m;
const DOC_REF = /\{@(?:link|linkplain|value)\s+([^}]*)\}|@(?:see|throws|exception)\s+(\S+(?:\([^)]*\))?)/g;
const IDENT = /[A-Za-z_$][\w$]*/g;

/** The code with every comment and literal blanked, and the doc comments' text. */
function split(text) {
  const code = [];
  const docs = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (text.startsWith("/*", i)) {
      const close = text.indexOf("*/", i + 2);
      const end = close < 0 ? n : close + 2;
      if (text.startsWith("/**", i) && !text.startsWith("/**/", i)) docs.push(text.slice(i, end));
      code.push(" ");
      i = end;
    } else if (text.startsWith("//", i)) {
      const close = text.indexOf("\n", i);
      i = close < 0 ? n : close;
    } else if (text.startsWith('"""', i)) {
      let end = i + 3;
      for (;;) {
        end = text.indexOf('"""', end);
        if (end < 0) {
          end = n;
          break;
        }
        if (text[end - 1] !== "\\") {
          end += 3;
          break;
        }
        end += 1;
      }
      code.push('""');
      i = end;
    } else if (text[i] === '"' || text[i] === "'") {
      const quote = text[i];
      let j = i + 1;
      while (j < n && text[j] !== quote && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
      code.push('""');
      i = j + 1;
    } else {
      code.push(text[i]);
      i += 1;
    }
  }
  return { code: code.join(""), docs };
}

/** The identifiers that stand unqualified in code: not right after a single dot (a varargs ... is not one). */
function codeNames(code) {
  const names = new Set();
  for (const m of code.matchAll(IDENT)) {
    let k = m.index - 1;
    while (k >= 0 && " \t\r\n".includes(code[k])) k -= 1;
    if (k >= 0 && code[k] === "." && code.slice(Math.max(0, k - 2), k + 1) !== "...") continue;
    names.add(m[0]);
  }
  return names;
}

/** The names javadoc resolves: each reference's first segment, and its signature's parameter types. */
function docNames(docs) {
  const names = new Set();
  for (const doc of docs) {
    for (const m of doc.matchAll(DOC_REF)) {
      const ref = (m[1] ?? m[2] ?? "").trim();
      const head = /^[\w$]+/.exec(ref);
      if (head) names.add(head[0]);
      const signature = /^[\w$.]*(?:#[\w$]*)?(\([^)]*\))?/.exec(ref)?.[1];
      if (!signature) continue;
      for (const param of signature.slice(1, -1).split(",")) {
        const type = /^\s*(?:final\s+)?([\w$]+)/.exec(param);
        if (type) names.add(type[1]);
      }
    }
  }
  return names;
}

const problems = [];
for (const file of files) {
  const text = readFileSync(join(root, file), "utf8");
  const pkg = PACKAGE.exec(text)?.[1] ?? "";
  const imports = [];
  const body = text
    .split("\n")
    .map((line, index) => {
      if (/^[ \t]*import\b/.test(line)) imports.push({ line, where: `${file}:${index + 1}` });
      return /^[ \t]*(import|package)\b/.test(line) ? "" : line;
    })
    .join("\n");
  const { code, docs } = split(body);
  const used = new Set([...codeNames(code), ...docNames(docs)]);
  const seen = new Set();
  for (const { line, where } of imports) {
    const m = SINGLE.exec(line);
    if (!m) {
      problems.push(`${where}: ${line.trim()} (not a single-type or single-member import, so not checked)`);
      continue;
    }
    const isStatic = m[1] !== undefined;
    const name = m[2];
    const dot = name.lastIndexOf(".");
    const simple = name.slice(dot + 1);
    const owner = dot < 0 ? "" : name.slice(0, dot);
    const label = `${isStatic ? "static " : ""}${name}`;
    if (seen.has(label)) problems.push(`${where}: ${label} (imported twice)`);
    else if (!used.has(simple)) problems.push(`${where}: ${label} (unused)`);
    else if (!isStatic && owner === "java.lang") problems.push(`${where}: ${label} (java.lang needs no import)`);
    else if (!isStatic && owner === pkg) problems.push(`${where}: ${label} (same package needs no import)`);
    seen.add(label);
  }
}

if (problems.length > 0) {
  for (const p of problems) console.error(p);
  console.error(`check-imports: ${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`check-imports: ok, ${files.length} Java files`);
