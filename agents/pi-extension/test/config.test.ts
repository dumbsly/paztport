// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { assertOutsideWorkspace, loadConfig, resolveConfigPath } from "../src/config.ts";

const tmp = realpathSync(mkdtempSync(join(tmpdir(), "paztport-config-")));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let n = 0;
function write(cfg: unknown): string {
  const dir = join(tmp, `c${n++}`);
  mkdirSync(dir);
  const path = join(dir, "paztport.json");
  writeFileSync(path, JSON.stringify(cfg));
  return path;
}

const base = { mode: "enforce", clientDir: "client", servers: [{ id: "github", command: "node", attested: true }] };

describe("loadConfig", () => {
  it("validConfigLoads", () => {
    const path = write({
      ...base,
      eventsLog: "events.jsonl",
      servers: [
        { id: "github", command: "node", args: ["a.js"], env: { K: "v" }, attested: true, pin: "my.pub" },
        { id: "docs_2-x", command: "node", attested: false },
      ],
    });
    const cfg = loadConfig(path);
    expect(cfg.mode).toBe("enforce");
    expect(cfg.servers).toHaveLength(2);
    expect(cfg.servers[0]).toMatchObject({ id: "github", command: "node", args: ["a.js"], env: { K: "v" }, attested: true });
    expect(cfg.servers[1]).toMatchObject({ id: "docs_2-x", attested: false });
    expect(cfg.servers[1]!.pin).toBeUndefined();
  });

  it("relativePathsResolveAgainstConfigDir", () => {
    const path = write({ ...base, eventsLog: "logs/events.jsonl", servers: [{ id: "a", command: "node", attested: true }, { id: "b", command: "node", attested: true, pin: "pins/b.pub" }, { id: "c", command: "node", attested: false }] });
    const dir = join(path, "..");
    const cfg = loadConfig(path);
    expect(cfg.clientDir).toBe(join(dir, "client"));
    expect(cfg.eventsLog).toBe(join(dir, "logs/events.jsonl"));
    expect(cfg.servers[0]!.pin).toBe(join(dir, "client", "server-policy.pub"));
    expect(cfg.servers[1]!.pin).toBe(join(dir, "pins/b.pub"));
    expect(cfg.servers[2]!.pin).toBeUndefined();
  });

  it("absolutePathsKept", () => {
    const cfg = loadConfig(write({ ...base, clientDir: "/abs/client" }));
    expect(cfg.clientDir).toBe("/abs/client");
  });

  it("badModeRejected", () => {
    expect(() => loadConfig(write({ ...base, mode: "strict" }))).toThrow(/mode/);
    expect(() => loadConfig(write({ ...base, mode: 1 }))).toThrow(/mode/);
  });

  it("badServerIdRejected", () => {
    for (const id of ["a.b", "a/b", "a|b", "", "a b"]) {
      expect(() => loadConfig(write({ ...base, servers: [{ id, command: "node", attested: true }] })), id).toThrow(/servers\[0\]\.id/);
    }
  });

  it("duplicateServerIdRejected", () => {
    const s = { id: "a", command: "node", attested: true };
    expect(() => loadConfig(write({ ...base, servers: [s, s] }))).toThrow(/servers\[1\]\.id/);
  });

  it("missingFieldsNamed", () => {
    expect(() => loadConfig(write({ clientDir: "c", servers: [] }))).toThrow(/mode/);
    expect(() => loadConfig(write({ mode: "enforce", servers: [] }))).toThrow(/clientDir/);
    expect(() => loadConfig(write({ mode: "enforce", clientDir: "c" }))).toThrow(/servers/);
    expect(() => loadConfig(write({ ...base, servers: [{ id: "a", attested: true }] }))).toThrow(/servers\[0\]\.command/);
    expect(() => loadConfig(write({ ...base, servers: [{ id: "a", command: "node" }] }))).toThrow(/servers\[0\]\.attested/);
    expect(() => loadConfig(write({ ...base, servers: [{ id: "a", command: "node", attested: true, args: [1] }] }))).toThrow(/servers\[0\]\.args/);
    expect(() => loadConfig(write({ ...base, servers: [{ id: "a", command: "node", attested: true, env: { K: 1 } }] }))).toThrow(/servers\[0\]\.env/);
    expect(() => loadConfig(write({ ...base, eventsLog: 5 }))).toThrow(/eventsLog/);
    expect(() => loadConfig(write([]))).toThrow(/config/);
  });

  it("unreadableOrInvalidJsonNamesPath", () => {
    expect(() => loadConfig(join(tmp, "missing.json"))).toThrow(/missing\.json/);
    const bad = join(tmp, "bad.json");
    writeFileSync(bad, "{nope");
    expect(() => loadConfig(bad)).toThrow(/bad\.json/);
  });
});

describe("resolveConfigPath", () => {
  it("flagBeatsEnv", () => {
    expect(resolveConfigPath("/f.json", { PAZTPORT_CONFIG: "/e.json" })).toBe("/f.json");
    expect(resolveConfigPath(undefined, { PAZTPORT_CONFIG: "/e.json" })).toBe("/e.json");
    expect(resolveConfigPath(undefined, {})).toBeUndefined();
    expect(resolveConfigPath("", { PAZTPORT_CONFIG: "" })).toBeUndefined();
  });
});

describe("assertOutsideWorkspace", () => {
  it("insideWorkspaceRejected", () => {
    const ws = join(tmp, "ws1");
    mkdirSync(join(ws, "keys"), { recursive: true });
    expect(() => assertOutsideWorkspace(join(ws, "keys"), ws)).toThrow(/workspace/);
    expect(() => assertOutsideWorkspace(ws, ws)).toThrow(/workspace/);
  });

  it("siblingDirAccepted", () => {
    const ws = join(tmp, "ws2");
    const sib = join(tmp, "ws2-keys");
    mkdirSync(ws);
    mkdirSync(sib);
    expect(() => assertOutsideWorkspace(sib, ws)).not.toThrow();
  });

  it("symlinkIntoWorkspaceRejected", () => {
    const ws = join(tmp, "ws3");
    const keys = join(ws, "keys");
    mkdirSync(keys, { recursive: true });
    const link = join(tmp, "innocent");
    symlinkSync(keys, link);
    expect(() => assertOutsideWorkspace(link, ws)).toThrow(/workspace/);
    const wsLink = join(tmp, "ws3-link");
    symlinkSync(ws, wsLink);
    expect(() => assertOutsideWorkspace(keys, wsLink)).toThrow(/workspace/);
  });

  it("dotDotPrefixedDirInsideRejected", () => {
    const ws = join(tmp, "ws4");
    mkdirSync(join(ws, "..keys"), { recursive: true });
    expect(() => assertOutsideWorkspace(join(ws, "..keys"), ws)).toThrow(/workspace/);
  });

  it("missingClientDirThrowsClearly", () => {
    expect(() => assertOutsideWorkspace(join(tmp, "nope"), tmp)).toThrow(/clientDir/);
  });

  it("namesWhatIsGuarded", () => {
    const ws = join(tmp, "ws5");
    mkdirSync(ws);
    writeFileSync(join(ws, "paztport.json"), "{}");
    expect(() => assertOutsideWorkspace(join(ws, "paztport.json"), ws, "config")).toThrow(/^config .* is inside the workspace/);
  });

  it("mayBeMissingChecksNearestExistingAncestor", () => {
    const ws = join(tmp, "ws6");
    mkdirSync(ws);
    const outside = join(tmp, "ws6-keys");
    mkdirSync(outside);
    const opts = { mayBeMissing: true };
    expect(() => assertOutsideWorkspace(join(ws, "a/b/pin.pub"), ws, "pin", opts)).toThrow(/^pin .* is inside the workspace/);
    expect(() => assertOutsideWorkspace(join(outside, "a/pin.pub"), ws, "pin", opts)).not.toThrow();
    // a symlinked ancestor is resolved before the missing rest is appended
    const link = join(tmp, "ws6-link");
    symlinkSync(ws, link);
    expect(() => assertOutsideWorkspace(join(link, "pin.pub"), ws, "pin", opts)).toThrow(/inside the workspace/);
    expect(() => assertOutsideWorkspace(join(link, "pin.pub"), ws, "pin")).toThrow(/cannot be resolved/);
  });
});
