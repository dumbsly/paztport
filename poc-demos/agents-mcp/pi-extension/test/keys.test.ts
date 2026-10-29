// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, signKeyring, signKeyringOldForm, signRoot, signRootOldForm, verifyKeyring, verifyProof, decode } from "@paztport/core";
import { WARN_WITHIN_MS } from "@paztport/mcp";
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
    // the root whole, its notAfter included, and the keyring's window beside its signature
    expect(m.signedRoot).toEqual(json(join(client, "root.json")));
    expect(m.signedRoot.notAfter).toEqual(expect.any(Number));
    expect(m.keyringNotAfter).toBe(ring.notAfter);
    expect(m.keyringNotAfter).toEqual(expect.any(Number));
    const routes = Object.keys(m.proofs);
    expect(routes).toContain("session/pi/mcp:github.list_issues");
    expect(routes).toHaveLength(9);
    const route = "session/pi/mcp:github.create_pull_request";
    expect(verifyProof(m.proofs[route]!, route, decode(m.signedRoot.root))).toBe(true);
    // least privilege: the root is checked with the policy public key alone, and setup-demo does not
    // leave the client policy private key behind
    expect(existsSync(join(client, "policy.key"))).toBe(false);
    expect(Object.keys(m).sort()).toEqual(["keyring", "keyringNotAfter", "keyringSig", "piKey", "policyPublicKey", "proofs", "sessionKey", "signedRoot"]);
  });

  it("carriesTheKeyringSignature", () => {
    const m = loadClientMaterial(client);
    expect(m.keyringSig).toBe(json(join(client, "keyring.json")).sig);
    expect(verifyKeyring({ policy: m.policyPublicKey, services: m.keyring, sig: m.keyringSig, notAfter: m.keyringNotAfter! }, m.policyPublicKey)).toBe(true);
  });

  it("aKeyringOrRootWindowThatDoesNotVerifyIsRejected", () => {
    const ringDir = copy();
    const ring = json(join(ringDir, "keyring.json"));
    writeFileSync(join(ringDir, "keyring.json"), JSON.stringify({ ...ring, notAfter: ring.notAfter + 1 }));
    expect(() => loadClientMaterial(ringDir)).toThrow("keyring.json is not signed by its policy key");
    const droppedDir = copy();
    const { notAfter: _w, ...dropped } = ring;
    writeFileSync(join(droppedDir, "keyring.json"), JSON.stringify(dropped));
    expect(() => loadClientMaterial(droppedDir)).toThrow("keyring.json is not signed by its policy key");
    const rootDir = copy();
    const root = json(join(rootDir, "root.json"));
    writeFileSync(join(rootDir, "root.json"), JSON.stringify({ ...root, notAfter: root.notAfter + 1 }));
    expect(() => loadClientMaterial(rootDir)).toThrow("root.json is not signed by the keyring.json policy key");
  });

  it.each([1.5, -1, 2 ** 53, "x", null, true])("aWindowThatIsNotAnIntegerIsRefused %j", (bad) => {
    const ringDir = copy();
    writeFileSync(join(ringDir, "keyring.json"), JSON.stringify({ ...json(join(ringDir, "keyring.json")), notAfter: bad }));
    expect(() => loadClientMaterial(ringDir)).toThrow("keyring.json notAfter must be an integer in [0, 2^53 - 1]");
    const rootDir = copy();
    writeFileSync(join(rootDir, "root.json"), JSON.stringify({ ...json(join(rootDir, "root.json")), notAfter: bad }));
    expect(() => loadClientMaterial(rootDir)).toThrow("root.json.notAfter must be an integer in [0, 2^53 - 1]");
    expect(() => loadClientMaterial(rootDir)).toThrow("npm run setup-demo -- --force");
  });

  /**
   * Signs the client keyring, root.json and local-tools/root.json again under a fresh policy key, each with the given
   * window (or the old form for "old"), the rest until 2100; returns the copy's directory.
   */
  function resigned(w: { ring?: number | "old"; root?: number | "old"; localRoot?: number | "old" }): string {
    const dir = copy();
    const policy = generateKeyPair();
    const ring = json(join(dir, "keyring.json"));
    const ringAt = w.ring ?? FAR;
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ringAt === "old" ? signKeyringOldForm(ring.services, policy.publicKey, policy.privateKey) : signKeyring(ring.services, policy.publicKey, policy.privateKey, ringAt)));
    for (const [path, at] of [["root.json", w.root], ["local-tools/root.json", w.localRoot]] as const) {
      const root = json(join(dir, path));
      const rootAt = at ?? FAR;
      writeFileSync(join(dir, path), JSON.stringify(rootAt === "old" ? signRootOldForm(decode(root.root), root.rootId, policy.privateKey) : signRoot(decode(root.root), root.rootId, policy.privateKey, rootAt)));
    }
    return dir;
  }
  const FIX = "npm run setup-demo -- --force";
  const FAR = 4_102_444_800_000;
  const T = 1_800_000_000_000;
  /** loadClientMaterial at `now`, with its warnings collected. */
  const load = (dir: string, policyDir: string, now: number) => {
    const warnings: string[] = [];
    loadClientMaterial(dir, policyDir, now, (m) => warnings.push(m));
    return warnings;
  };

  it("clientRefusesOldFormMaterial", () => {
    // an old-form keyring or root has no window, so it is never current: refused at startup, naming the file and the fix
    const ring = resigned({ ring: "old" });
    expect(() => loadClientMaterial(ring)).toThrow(`${join(ring, "keyring.json")} is in the old form (no notAfter): regenerate`);
    expect(() => loadClientMaterial(ring)).toThrow(FIX);
    const root = resigned({ root: "old" });
    expect(() => loadClientMaterial(root)).toThrow(`${join(root, "root.json")} is in the old form (no notAfter): regenerate`);
    expect(() => loadClientMaterial(root)).toThrow(FIX);
    const local = resigned({ localRoot: "old" });
    expect(() => loadClientMaterial(local)).not.toThrow();
    expect(() => loadClientMaterial(local, join(local, "local-tools"))).toThrow(`${join(local, "local-tools/root.json")} is in the old form`);
  });

  it("clientRefusesExpiredOwnRoot", () => {
    const dir = resigned({ root: T });
    // at notAfter it still counts; one ms after it does not
    expect(load(dir, dir, T - WARN_WITHIN_MS - 1)).toEqual([]);
    expect(() => load(dir, dir, T)).not.toThrow();
    expect(() => load(dir, dir, T + 1)).toThrow(`${join(dir, "root.json")} expired at ${T} (${new Date(T).toISOString()}): regenerate`);
    expect(() => load(dir, dir, T + 1)).toThrow(FIX);
  });

  it("clientRefusesExpiredLocalToolsRoot", () => {
    const dir = resigned({ localRoot: T });
    const lt = join(dir, "local-tools");
    expect(() => load(dir, lt, T)).not.toThrow();
    expect(() => load(dir, lt, T + 1)).toThrow(`${join(lt, "root.json")} expired at ${T}`);
    // the client root beside it is not the one this run uses
    expect(() => load(dir, dir, T + 1)).not.toThrow();
  });

  it("clientRefusesExpiredKeyring", () => {
    const dir = resigned({ ring: T });
    expect(() => load(dir, dir, T)).not.toThrow();
    expect(() => load(dir, dir, T + 1)).toThrow(`${join(dir, "keyring.json")} expired at ${T}`);
    expect(() => load(dir, join(dir, "local-tools"), T + 1)).toThrow(FIX);
  });

  it("nearExpiryWarnsNamingTheFileAndWindow", () => {
    const dir = resigned({ ring: T, root: T + 1000, localRoot: T + 2000 });
    expect(load(dir, dir, T - WARN_WITHIN_MS - 1)).toEqual([]);
    expect(load(dir, dir, T - WARN_WITHIN_MS)).toEqual([
      `paztport: ${join(dir, "keyring.json")} expires soon (notAfter ${T} (${new Date(T).toISOString()})); regenerate the demo keys with ${FIX}`,
    ]);
    expect(load(dir, join(dir, "local-tools"), T + 2000 - WARN_WITHIN_MS)).toEqual([
      expect.stringContaining(`${join(dir, "keyring.json")} expires soon`),
      expect.stringContaining(`${join(dir, "local-tools/root.json")} expires soon (notAfter ${T + 2000}`),
    ]);
  });

  it("messagesNamingAWindowNeverThrow", () => {
    // past Date's range a window is named by its integer alone
    const big = 8_900_000_000_000_000;
    const dir = resigned({ root: big });
    expect(() => load(dir, dir, big + 1)).toThrow(`${join(dir, "root.json")} expired at ${big}: regenerate`);
    const top = Number.MAX_SAFE_INTEGER;
    const max = resigned({ ring: top, root: top });
    expect(load(max, max, top)).toEqual([expect.stringContaining(`expires soon (notAfter ${top})`), expect.stringContaining(`expires soon (notAfter ${top})`)]);
  });

  it("anUnsignedKeyringNamesTheFix", () => {
    // a keyring.json from before keyrings were signed
    const dir = copy();
    const { sig: _sig, ...ring } = json(join(dir, "keyring.json"));
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ring));
    expect(() => loadClientMaterial(dir)).toThrow("npm run setup-demo -- --force");
  });

  it("aKeyringSignatureThatFailsIsRejectedAndNamesTheFix", () => {
    const dir = copy();
    const ring = json(join(dir, "keyring.json"));
    ring.services.extra = generateKeyPair().publicKey;
    writeFileSync(join(dir, "keyring.json"), JSON.stringify(ring));
    expect(() => loadClientMaterial(dir)).toThrow("keyring.json is not signed by its policy key");
    expect(() => loadClientMaterial(dir)).toThrow("npm run setup-demo -- --force");
  });

  it.each([7, null, {}])("aNonStringKeyringSignatureNamesTheFix %j", (sig) => {
    const dir = copy();
    const ring = json(join(dir, "keyring.json"));
    writeFileSync(join(dir, "keyring.json"), JSON.stringify({ ...ring, sig }));
    expect(() => loadClientMaterial(dir)).toThrow("keyring.json sig must be a string");
    expect(() => loadClientMaterial(dir)).toThrow("npm run setup-demo -- --force");
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
