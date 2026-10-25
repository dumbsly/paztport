// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The paths named by placeholder in signed local input: every spelling known for the workspace (as pi
 * was given it, and as it resolves) and for the home folder.
 */
export type Places = { workspace: readonly string[]; home: readonly string[] };

/** What may stand right before a named path: the start, a space, a quote, a bracket, "=", ":", "," or a shell operator. */
const BEFORE = String.raw`\s"'\x60;|&<>()=:,\[{`;
/** What may follow a named path: the end, "/", or any of the above or a closing bracket. */
const AFTER = String.raw`/\s"'\x60;|&<>()=:,\]}`;

/** Escapes `s` for use inside a RegExp. */
const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A copy of `v` in which every string (keys too) names the workspace as "<workspace>" and the home folder
 * as "<home>", wherever one of their spellings appears as a whole path: after the start or a separator,
 * and followed by "/", the end or a separator. A folder whose name only starts with the workspace's
 * ("proj.bak", "projx") is a different folder, and a path that only contains one partway through is left
 * alone. The longest spelling wins, so a workspace under home is named as the workspace.
 *
 * A "<" already in the input is written "<<", so a single "<" only ever opens a placeholder, and the input
 * reads back exactly (see decodePlaceholders) except for which spelling of the workspace or home it used.
 * Throws when two keys of one object would encode to the same key. The recorded input is this encoding,
 * not a command to run.
 */
export function encodePlaceholders<T>(v: T, places: Places): T {
  const spellings = new Map<string, string>();
  for (const [token, paths] of [["<workspace>", places.workspace], ["<home>", places.home]] as const) {
    for (const p of paths) {
      // only absolute paths, and "/" alone is no prefix to replace; the first token named for a spelling keeps it
      if (p.startsWith("/") && p.length > 1 && !spellings.has(p.replaceAll("<", "<<"))) spellings.set(p.replaceAll("<", "<<"), token);
    }
  }
  const alternatives = [...spellings.keys()].sort((a, b) => b.length - a.length).map(escapeRegExp);
  const re = alternatives.length === 0 ? undefined : new RegExp(`(?<=^|[${BEFORE}])(?:${alternatives.join("|")})(?=$|[${AFTER}])`, "g");
  const str = (s: string): string => {
    const escaped = s.replaceAll("<", "<<");
    return re === undefined ? escaped : escaped.replace(re, (m) => spellings.get(m)!);
  };
  const copy = (x: unknown): unknown => {
    if (typeof x === "string") return str(x);
    if (Array.isArray(x)) return x.map(copy);
    if (typeof x === "object" && x !== null) {
      const out: Record<string, unknown> = {};
      for (const [k, e] of Object.entries(x)) {
        const key = str(k);
        // two spellings of one folder as keys would merge and drop an entry from the signed record
        if (Object.hasOwn(out, key)) throw new Error(`two keys encode to the same key: ${key}`);
        Object.defineProperty(out, key, { value: copy(e), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    return x;
  };
  return copy(v) as T;
}

/**
 * An input encodePlaceholders could have been given, with each placeholder read back as the one path given
 * here: exact, except that every spelling of a folder reads back as this one.
 * Throws on a "<" that opens neither "<<" nor a placeholder.
 */
export function decodePlaceholders<T>(v: T, paths: { workspace: string; home: string }): T {
  const str = (s: string): string => {
    let out = "";
    for (let i = 0; i < s.length; ) {
      if (s[i] !== "<") {
        out += s[i++];
      } else if (s.startsWith("<<", i)) {
        out += "<";
        i += 2;
      } else if (s.startsWith("<workspace>", i)) {
        out += paths.workspace;
        i += "<workspace>".length;
      } else if (s.startsWith("<home>", i)) {
        out += paths.home;
        i += "<home>".length;
      } else {
        throw new Error(`not a placeholder at ${i}`);
      }
    }
    return out;
  };
  const copy = (x: unknown): unknown => {
    if (typeof x === "string") return str(x);
    if (Array.isArray(x)) return x.map(copy);
    if (typeof x === "object" && x !== null) return Object.fromEntries(Object.entries(x).map(([k, e]) => [str(k), copy(e)]));
    return x;
  };
  return copy(v) as T;
}
