// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, verifyKeyring, verifyProof, decode } from "@paztport/core";
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
    // least privilege: the root is checked with the policy public key alone, and setup-demo does not
    // leave the client policy private key behind
    expect(existsSync(join(client, "policy.key"))).toBe(false);
    expect(Object.keys(m).sort()).toEqual(["keyring", "keyringSig", "piKey", "policyPublicKey", "proofs", "sessionKey", "signedRoot"]);
  });

  it("carriesTheKeyringSignature", () => {
    const m = loadClientMaterial(client);
    expect(m.keyringSig).toBe(json(join(client, "keyring.json")).sig);
    expect(verifyKeyring({ policy: m.policyPublicKey, services: m.keyring, sig: m.keyringSig }, m.policyPublicKey)).toBe(true);
  });

  it("anUnsignedKeyringNamesTheFix", () => {
    // a keyring.json from before keyrings were signed
    const dir = copy();
    const { sig: _sig, ...ring } = json(join(dir, "keyring.json"));
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ring));
    expect(() => loadClientMaterial(dir)).toThrow("npm run setup-demo -- --force");
  });

  it("aKeyringSignatureThatFailsIsRejected", () => {
    const dir = copy();
    const ring = json(join(dir, "keyring.json"));
    ring.services.extra = generateKeyPair().publicKey;
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ring));
    expect(() => loadClientMaterial(dir)).toThrow("keyring.json is not signed by its policy key");
  });

  it("loadsSignedLocalRules", () => {
    const m = loadClientMaterial(client, join(client, "local-tools"));
    expect(m.rules).toEqual({
      v: 1,
      folders: [
        { path: ".", access: ["read"] },
        { path: "website", access: ["read", "write"], label: "public", destination: "public" },
        { path: "notes", access: ["read", "write"], destination: "private" },
      ],
      programs: ["cat", "head", "tail", "wc", "grep", "ls", "diff", "pwd", "echo", "cut", "tr", "basename", "dirname", "test", "true", "false", "mkdir", "touch", "cp", "mv"],
    });
    expect(loadClientMaterial(client).rules).toBeUndefined();
  });

  it("editedRulesRejected", () => {
    const dir = copy();
    const lt = join(dir, "local-tools");
    const rules = json(join(lt, "rules.json"));
    rules.folders[1].label = "private";
    writeFileSync(join(lt, "rules.json"), JSON.stringify(rules));
    expect(() => loadClientMaterial(dir, lt)).toThrow(/not covered by the signed client root/);
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
