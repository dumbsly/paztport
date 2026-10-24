// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, verifyProof, decode } from "@paztport/path-attest";
import { loadClientMaterial, readPin } from "../src/keys.ts";

const SETUP = join(import.meta.dirname, "../../scripts/setup-demo.ts");
const tmp = mkdtempSync(join(tmpdir(), "paztport-keys-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let client: string;
let n = 0;
beforeAll(() => {
  const out = join(tmp, "demo");
  const r = spawnSync(process.execPath, [SETUP, "--out", out], { encoding: "utf8" });
  expect(r.status, r.stderr).toBe(0);
  client = join(out, "client");
});

/** A fresh copy of the client directory to corrupt. */
function copy(): string {
  const dir = join(tmp, `copy${n++}`);
  cpSync(client, dir, { recursive: true });
  return dir;
}

const json = (path: string) => JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;

describe("loadClientMaterial", () => {
  it("loadsSetupDemoOutput", () => {
    const m = loadClientMaterial(client);
    const ring = json(join(client, "keyring.json"));
    expect(m.sessionKey).toBe(readFileSync(join(client, "session.key"), "utf8").trim());
    expect(m.piKey).toBe(readFileSync(join(client, "pi.key"), "utf8").trim());
    expect(m.policyPublicKey).toBe(ring.policy);
    expect(m.keyring).toEqual(ring.services);
    expect(m.signedRoot.rootId).toBe(json(join(client, "root.json")).rootId);
    const routes = Object.keys(m.proofs);
    expect(routes).toContain("session/pi/mcp:github.list_issues");
    expect(routes).toHaveLength(9);
    const route = "session/pi/mcp:github.create_pull_request";
    expect(verifyProof(m.proofs[route]!, route, decode(m.signedRoot.root))).toBe(true);
  });

  it("policyPrivateKeyNotRead", () => {
    // least privilege: verifying the root needs only the public key, so policy.key is never read
    const secret = readFileSync(join(client, "policy.key"), "utf8").trim();
    expect(JSON.stringify(loadClientMaterial(client))).not.toContain(secret);
    const dir = copy();
    rmSync(join(dir, "policy.key"));
    expect(Object.keys(loadClientMaterial(dir)).sort()).toEqual(["keyring", "piKey", "policyPublicKey", "proofs", "sessionKey", "signedRoot"]);
  });

  it("mismatchedKeyRejected", () => {
    for (const name of ["session", "pi"]) {
      const dir = copy();
      writeFileSync(join(dir, `${name}.key`), generateKeyPair().privateKey + "\n");
      expect(() => loadClientMaterial(dir), name).toThrow(new RegExp(`${name}\\.key`));
    }
  });

  it("tamperedRootRejected", () => {
    const dir = copy();
    const root = json(join(dir, "root.json"));
    root.root = root.root.slice(0, -2) + (root.root.endsWith("AA") ? "BB" : "AA");
    writeFileSync(join(dir, "root.json"), JSON.stringify(root));
    expect(() => loadClientMaterial(dir)).toThrow(/root\.json/);
  });

  it("badProofRejected", () => {
    const dir = copy();
    const bundle = json(join(dir, "proofs-pi.json"));
    bundle.proofs["session/pi/mcp:github.list_issues"].siblings = "nope";
    writeFileSync(join(dir, "proofs-pi.json"), JSON.stringify(bundle));
    expect(() => loadClientMaterial(dir)).toThrow(/mcp:github\.list_issues/);
  });

  it("missingFileNamed", () => {
    const dir = copy();
    rmSync(join(dir, "pi.key"));
    expect(() => loadClientMaterial(dir)).toThrow(/pi\.key/);
  });

  it("keyringMissingEntryRejected", () => {
    const dir = copy();
    const ring = json(join(dir, "keyring.json"));
    delete ring.services.pi;
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ring));
    expect(() => loadClientMaterial(dir)).toThrow(/keyring\.json.*pi/);
  });
});

describe("readPin", () => {
  it("pinRead", () => {
    const pin = readPin(join(client, "server-policy.pub"));
    expect(pin).toBe(json(join(tmp, "demo/server/keyring.json")).policy);
    const p = join(tmp, "pin.pub");
    writeFileSync(p, "  abc\n\n");
    expect(readPin(p)).toBe("abc");
  });
});
