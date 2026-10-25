// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A local-tools run's evidence and events, made by driving the extension's real LocalGate and a real
// attested MCP session against the mock server: nothing here is hand-written JSON.

import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { RULES_ROUTE_PREFIX, rulesHash } from "@paztport/path-attest";
import { ServerConnection } from "../../../pi-extension/src/connection.ts";
import { EventLog } from "../../../pi-extension/src/events.ts";
import { EvidenceLog } from "../../../pi-extension/src/evidence.ts";
import { InfluenceStore } from "../../../pi-extension/src/influence.ts";
import { loadClientMaterial, type ClientMaterial } from "../../../pi-extension/src/keys.ts";
import { LocalGate } from "../../../pi-extension/src/local/gate.ts";
import { RunState } from "../../../pi-extension/src/runs.ts";
import { githubArgs } from "../../../pi-extension/test/helpers/demo.ts";

export const LOCAL_PROMPT = "Fix the README typo.";

export type LocalRun = {
  runDir: string;
  evidencePath: string;
  eventsPath: string;
  outcomePath: string;
  material: ClientMaterial;
};

/** The client record as the extension writes it at session_start in enforce mode. */
function clientRecord(material: ClientMaterial) {
  const rules = material.rules ?? null;
  const route = rules !== null ? `session/pi/${RULES_ROUTE_PREFIX}${rulesHash(rules)}` : undefined;
  return {
    v: 1 as const,
    type: "client" as const,
    keyring: material.keyring,
    policyPublicKey: material.policyPublicKey,
    signedRoot: material.signedRoot,
    rules,
    rulesProof: route !== undefined && Object.hasOwn(material.proofs, route) ? material.proofs[route]! : null,
  };
}

/**
 * One run in `runDir` (evidence.jsonl, events.jsonl, outcome.jsonl, workspace/) with the demo keys in `demo`.
 * With `rules: false` the client material has no local rules (the phase-1 client root), so every local call
 * is refused as out of scope. The calls, by call id:
 * - l_read: read website/README.md, allowed (its public label is recorded as the extension does)
 * - l_outside: read /etc/hosts, refused (resolved as "outside")
 * - l_note: write notes/n.md, allowed
 * - l_route: a tool with no local route, refused (no proof)
 * - l_uncheck: a bash command with a $ expansion, refused as uncheckable
 * - toolu_a, toolu_c: MCP reads of the planted issue (third-party) and the private notes (private)
 * - l_leak: write website/x.md after both reads, refused by the influence rule
 * - toolu_d: an MCP public write, refused by the server
 */
export async function localRun(demo: string, runDir: string, opts: { rules?: boolean } = {}): Promise<LocalRun> {
  mkdirSync(runDir, { recursive: true });
  const dir = realpathSync.native(runDir);
  const workspace = join(dir, "workspace");
  for (const d of ["website", "notes", "secret"]) mkdirSync(join(workspace, d), { recursive: true });
  writeFileSync(join(workspace, "website", "README.md"), "# Acme\n");
  const material = opts.rules === false ? loadClientMaterial(join(demo, "client")) : loadClientMaterial(join(demo, "client"), join(demo, "client/local-tools"));
  const evidencePath = join(dir, "evidence.jsonl");
  const eventsPath = join(dir, "events.jsonl");
  const outcomePath = join(dir, "outcome.jsonl");
  const evidence = new EvidenceLog(evidencePath);
  const events = new EventLog(eventsPath);
  const influence = new InfluenceStore();
  const runs = new RunState();
  const conn = new ServerConnection(
    { id: "github", command: process.execPath, args: githubArgs(demo, "enforce", outcomePath), attested: true, pin: join(demo, "client/server-policy.pub") },
    "enforce",
    material,
    influence,
    runs,
    events,
    undefined,
    evidence,
  );
  evidence.write(clientRecord(material));
  const gate = new LocalGate({ mode: "enforce", material, influence, runs, events, evidence, now: Date.now, workspace, refused: [join(workspace, "secret")] });
  try {
    await conn.connect();
    const ts = Date.now();
    runs.start(LOCAL_PROMPT, ts);
    evidence.write({ v: 1, type: "run", rid: runs.current()!.rid, ts, prompt: LOCAL_PROMPT });
    gate.check("read", { path: "website/README.md" }, "l_read");
    // what the extension's tool_result handler records for an allowed local read
    const labels = gate.labelsFor("l_read");
    if (labels !== undefined) influence.recordClasses("local:read", labels, "h-read");
    gate.check("read", { path: "/etc/hosts" }, "l_outside");
    gate.check("write", { path: "notes/n.md", content: "note\n" }, "l_note");
    gate.check("other_tool", { x: 1 }, "l_route");
    gate.check("bash", { command: "cat $HOME/x" }, "l_uncheck");
    await conn.call("list_issues", { owner: "acme", repo: "website" }, "toolu_a");
    await conn.call("get_file_contents", { owner: "acme", repo: "payroll-notes", path: "README.md" }, "toolu_c");
    gate.check("write", { path: "website/x.md", content: "leak\n" }, "l_leak");
    await conn.call("create_branch", { owner: "acme", repo: "website", branch: "leak" }, "toolu_d");
  } finally {
    await conn.close();
  }
  return { runDir: dir, evidencePath, eventsPath, outcomePath, material };
}

/** The non-empty lines of a JSONL file. */
export const jsonLines = (path: string): string[] => readFileSync(path, "utf8").split("\n").filter(Boolean);
