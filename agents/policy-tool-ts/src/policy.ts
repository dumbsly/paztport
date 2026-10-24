// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { buildPolicy, DEFAULT_DEPTH } from "@paztport/path-attest";
import { parse } from "yaml";
import { readKey, writeJson } from "./files.ts";

const USAGE = "Usage: node policy.ts --paths <yaml> --policy-key <file> --out <dir> [--depth 8]";

/** Route node names become path segments, file names and "/"-joined routes: keep them unambiguous. */
function validNode(n: string): boolean {
  return (
    n.length > 0 &&
    n !== "." &&
    n !== ".." &&
    !n.includes("/") &&
    !n.includes("\\") &&
    !n.includes("|") &&
    !/\p{Surrogate}/u.test(n)
  );
}

function fail(): never {
  console.error(USAGE);
  process.exit(2);
}

function main(): void {
  let values: { paths?: string; "policy-key"?: string; out?: string; depth?: string };
  try {
    values = parseArgs({
      options: {
        paths: { type: "string" },
        "policy-key": { type: "string" },
        out: { type: "string" },
        depth: { type: "string" },
      },
      strict: true,
    }).values;
  } catch {
    return fail();
  }
  const { paths, "policy-key": keyFile, out } = values;
  if (!paths || !keyFile || !out) fail();
  const depth = values.depth === undefined ? DEFAULT_DEPTH : Number(values.depth);
  if (!Number.isInteger(depth) || depth < 1) fail();

  const doc = parse(readFileSync(paths, "utf8")) as { paths?: unknown };
  const routes = doc?.paths;
  if (
    !Array.isArray(routes) ||
    !routes.every((r) => Array.isArray(r) && r.length > 0 && r.every((n) => typeof n === "string"))
  ) {
    console.error(`policy: ${paths} must contain "paths: [[svc, ...], ...]"`);
    process.exit(2);
  }
  if (!(routes as string[][]).every((r) => r.every(validNode))) fail();

  const { signedRoot, bundles } = buildPolicy(routes as string[][], depth, readKey(keyFile));
  writeJson(join(out, "root.json"), signedRoot);
  for (const bundle of Object.values(bundles)) {
    writeJson(join(out, `proofs-${bundle.service}.json`), bundle);
  }
  console.log(`policy: wrote root ${signedRoot.rootId} and per-service bundles to ${out}`);
}

main();
