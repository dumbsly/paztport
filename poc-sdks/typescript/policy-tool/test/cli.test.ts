// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decode, sign, utf8, verify, verifyProof, verifyRoot } from "@paztport/core";
import type { MerkleProof, ProofBundle, SignedRoot } from "@paztport/core";
import { readJson, readKey, readKeyring } from "../src/files.ts";

const here = dirname(fileURLToPath(import.meta.url));
const keygen = resolve(here, "../src/keygen.ts");
const policy = resolve(here, "../src/policy.ts");

function run(script: string, args: string[]) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "paztport-cli-"));
}

describe("policy-tool CLIs", () => {
  it("keygenWritesKeysAndKeyring", () => {
    const out = tmp();
    const r = run(keygen, ["--out", out, "--services", "a,b,c"]);
    expect(r.status).toBe(0);
    const ring = readKeyring(join(out, "keyring.json"));
    expect(Object.keys(ring.services)).toEqual(["a", "b", "c"]);
    const msg = utf8("hello");
    for (const [name, pub] of [...Object.entries(ring.services), ["policy", ring.policy]] as const) {
      const priv = readKey(join(out, `${name}.key`));
      expect(verify(pub, msg, sign(priv, msg))).toBe(true);
    }
  });

  it("privateKeysAreOwnerOnly", () => {
    if (process.platform === "win32") return;
    const out = tmp();
    for (let i = 0; i < 2; i++) {
      expect(run(keygen, ["--out", out, "--services", "a,b"]).status).toBe(0);
      const keys = readdirSync(out).filter((f) => f.endsWith(".key"));
      expect(keys.sort()).toEqual(["a.key", "b.key", "policy.key"]);
      for (const f of keys) expect(statSync(join(out, f)).mode & 0o077).toBe(0);
    }
    // pre-existing permissive file is tightened on re-run
    chmodSync(join(out, "a.key"), 0o644);
    expect(run(keygen, ["--out", out, "--services", "a,b"]).status).toBe(0);
    expect(statSync(join(out, "a.key")).mode & 0o077).toBe(0);
  });

  it("keygenRejectsBadServiceNames", () => {
    for (const svc of ["a,a", "a/b", "a\\b", "..", ".", "policy", "keyring", "a,,b,policy"]) {
      const out = tmp();
      const r = run(keygen, ["--out", out, "--services", svc]);
      expect(r.status, svc).toBe(2);
      expect(r.stderr).toContain("Usage");
      expect(readdirSync(out)).toEqual([]);
    }
  });

  it("keygenRejectsCaseInsensitiveDuplicates", () => {
    for (const svc of ["A,a", "Policy", "KEYRING", "orders,Orders"]) {
      const out = tmp();
      const r = run(keygen, ["--out", out, "--services", svc]);
      expect(r.status, svc).toBe(2);
      expect(r.stderr).toContain("Usage");
      expect(readdirSync(out)).toEqual([]);
    }
  });

  it("policyRejectsBadNodeNames", () => {
    const keys = tmp();
    expect(run(keygen, ["--out", keys, "--services", "gateway"]).status).toBe(0);
    for (const node of ['""', '"a/b"', '"a\\\\b"', '"a|b"', '"."', '".."', '"x\\ud800"']) {
      const out = tmp();
      const yamlPath = join(keys, "paths.yaml");
      writeFileSync(yamlPath, `paths:\n  - [gateway, ${node}]\n`);
      const r = run(policy, ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--out", out]);
      expect(r.status, node).toBe(2);
      expect(r.stderr, node).toContain("Usage");
      expect(readdirSync(out), node).toEqual([]);
    }
  });

  it("policyBuildsRootAndBundles", () => {
    const keys = tmp();
    const out = tmp();
    expect(run(keygen, ["--out", keys, "--services", "gateway,orders,payment,search"]).status).toBe(0);
    const yamlPath = join(keys, "paths.yaml");
    writeFileSync(
      yamlPath,
      "paths:\n  - [gateway, orders, payment]\n  - [gateway, orders]\n  - [gateway, search]\n",
    );
    const r = run(policy, ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--out", out]);
    expect(r.status).toBe(0);
    const ring = readKeyring(join(keys, "keyring.json"));
    const root = readJson<SignedRoot>(join(out, "root.json"));
    expect(verifyRoot(root, ring.policy)).toBe(true);
    expect(root.rootId).toBe("v3c261c950069");
    const bundle = readJson<ProofBundle>(join(out, "proofs-orders.json"));
    const proof: MerkleProof | undefined = bundle.proofs["gateway/orders/payment"];
    expect(proof).toBeDefined();
    expect(verifyProof(proof as MerkleProof, "gateway/orders/payment", decode(root.root))).toBe(true);
  });

  it("policyReadsJavaKeyring", (ctx) => {
    const p = resolve(here, "../../../../out/keys/keyring.json");
    if (!existsSync(p)) ctx.skip();
    const ring = readKeyring(p);
    expect(typeof ring.policy).toBe("string");
    expect(Object.keys(ring.services).length).toBeGreaterThan(0);
    expect(readFileSync(p, "utf8")).toContain("services");
  });

  it("badArgsExitNonZero", () => {
    const r = run(keygen, ["--services", "a"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("Usage");
    const p = run(policy, ["--paths", "x"]);
    expect(p.status).toBe(2);
    expect(p.stderr).toContain("Usage");
  });
});
