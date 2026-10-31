// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Shared test setup: demo keys from scripts/setup-demo.ts and the real mock servers.

import { spawnSync } from "node:child_process";
import { cpSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decode, generateKeyPair, signReplyCert, signKeyring, signRoot, type ReplyCert, type SignedKeyring, type SignedRoot } from "@paztport/core";

const MOCK = join(import.meta.dirname, "../../../mock-github-mcp/src");
export const MAIN = join(MOCK, "main.ts");
export const DOCS = join(MOCK, "docs-main.ts");
export const STUB = join(import.meta.dirname, "stub-server.ts");
const SETUP = join(import.meta.dirname, "../../../scripts/setup-demo.ts");
export const CANARY = "c0ffee";
/** What the model is told for an INFLUENCE_DENIED or UNSAFE_SESSION refusal; written out here so a test pins the wording. */
export const UNSAFE_TEXT =
  "Paztport stopped this action. The system flagged it as unsafe, and it was not carried out. Actions like it stay " +
  "blocked for the rest of this session, so retrying it or trying another way will not work. A stop like this is the " +
  "system doing what the user wants. It is not a fault on your part. End your turn now and tell the user that the " +
  "system flagged actions you attempted as unsafe, and that they should review the logs.";

/** Generates demo keys and policies into <dir>/demo (server/ and client/) and returns that path. */
export function setupDemo(dir: string): string {
  const demo = join(dir, "demo");
  const r = spawnSync(process.execPath, [SETUP, "--out", demo], { encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`setup-demo failed: ${r.stderr}`);
  }
  return demo;
}

/** Arguments for the mock GitHub server (run with process.execPath). */
export function githubArgs(demo: string, mode: "enforce" | "audit" | "off", outcomeLog: string): string[] {
  return [MAIN, "--mode", mode, "--config", join(demo, "server"), "--outcome-log", outcomeLog, "--canary", CANARY];
}

/** The lines of a JSONL file, parsed. */
export const records = (path: string): Record<string, any>[] =>
  readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** The windows `resignDemo` gives; each one left out keeps the window it had. */
export type DemoWindows = { clientKeyring?: number; clientRoot?: number; localToolsRoot?: number; serverKeyring?: number; serverRoot?: number };

/**
 * A copy of `demo` at `to` whose client and server material is signed again under fresh policy keys (setup-demo
 * deletes the originals), with each window from `windows` or as it was, and both pins updated: the same services,
 * trees and proofs, so it runs as the original does. The reply certificate keeps its own window. Returns `to`.
 */
export function resignDemo(demo: string, to: string, windows: DemoWindows): string {
  cpSync(demo, to, { recursive: true });
  const json = <T>(path: string): T => JSON.parse(readFileSync(join(to, path), "utf8")) as T;
  const put = (path: string, v: unknown) => writeFileSync(join(to, path), JSON.stringify(v, null, 2) + "\n");
  const ring = (path: string, key: { publicKey: string; privateKey: string }, notAfter: number | undefined) => {
    const old = json<SignedKeyring>(path);
    put(path, signKeyring(old.services, key.publicKey, key.privateKey, notAfter ?? old.notAfter!));
  };
  const root = (path: string, key: { privateKey: string }, notAfter: number | undefined) => {
    const old = json<SignedRoot>(path);
    put(path, signRoot(decode(old.root), old.rootId, key.privateKey, notAfter ?? old.notAfter!));
  };
  const client = generateKeyPair();
  ring("client/keyring.json", client, windows.clientKeyring);
  root("client/root.json", client, windows.clientRoot);
  root("client/local-tools/root.json", client, windows.localToolsRoot);
  writeFileSync(join(to, "server/client-policy.pub"), client.publicKey + "\n");
  const server = generateKeyPair();
  ring("server/keyring.json", server, windows.serverKeyring);
  root("server/root.json", server, windows.serverRoot);
  const cert = json<ReplyCert>("server/reply-cert.json");
  put("server/reply-cert.json", signReplyCert(server.publicKey, cert.svc, cert.key, cert.notAfter, server.privateKey));
  writeFileSync(join(to, "client/server-policy.pub"), server.publicKey + "\n");
  return to;
}
