// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decode, sign, signKeyringOldForm, utf8, verify, verifyKeyring, verifyProof, verifyReplyCert, verifyRoot } from "@paztport/core";
import type { MerkleProof, ProofBundle, ReplyCert, SignedKeyring, SignedRoot } from "@paztport/core";
import { readJson, readKey, readKeyring } from "../src/files.ts";

const here = dirname(fileURLToPath(import.meta.url));
const keygen = resolve(here, "../src/keygen.ts");
const policy = resolve(here, "../src/policy.ts");

function run(script: string, args: string[]) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

/** The repo root: the nearest folder above this test that holds both the SDK and the demo trees. */
function repoRoot(): string {
  for (let d = here; ; d = dirname(d)) {
    if (existsSync(join(d, "poc-sdks")) && existsSync(join(d, "poc-demos"))) return d;
    if (dirname(d) === d) throw new Error(`no repo root above ${here}`);
  }
}

const DAY_MS = 86_400_000;

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

  it("keygenSignsTheKeyringWithThePolicyKey", () => {
    const out = tmp();
    const before = Date.now();
    expect(run(keygen, ["--out", out, "--services", "a,b"]).status).toBe(0);
    const after = Date.now();
    const ring = readKeyring(join(out, "keyring.json"));
    expect(typeof ring.sig).toBe("string");
    // the new form, valid for seven days
    expect(Object.keys(readJson<object>(join(out, "keyring.json")))).toEqual(["services", "policy", "sig", "notAfter"]);
    expect(ring.notAfter).toBeGreaterThanOrEqual(before + 7 * DAY_MS);
    expect(ring.notAfter).toBeLessThanOrEqual(after + 7 * DAY_MS);
    expect(verifyKeyring(ring as SignedKeyring, ring.policy)).toBe(true);
    const { notAfter: _w, ...dropped } = ring;
    expect(verifyKeyring(dropped as SignedKeyring, ring.policy)).toBe(false);
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
    const before = Date.now();
    const r = run(policy, ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--out", out]);
    const after = Date.now();
    expect(r.status).toBe(0);
    const ring = readKeyring(join(keys, "keyring.json"));
    const root = readJson<SignedRoot>(join(out, "root.json"));
    expect(verifyRoot(root, ring.policy)).toBe(true);
    // the new form, valid for seven days, and the window is printed
    expect(Object.keys(root)).toEqual(["rootId", "root", "sig", "notAfter"]);
    expect(root.notAfter).toBeGreaterThanOrEqual(before + 7 * DAY_MS);
    expect(root.notAfter).toBeLessThanOrEqual(after + 7 * DAY_MS);
    expect(r.stdout).toContain(`notAfter ${root.notAfter}`);
    expect(root.rootId).toMatch(/^v[0-9a-f]{12}$/);
    const bundle = readJson<ProofBundle>(join(out, "proofs-orders.json"));
    const proof: MerkleProof | undefined = bundle.proofs["gateway/orders/payment"];
    expect(proof).toBeDefined();
    expect(verifyProof(proof as MerkleProof, "gateway/orders/payment", decode(root.root))).toBe(true);
  });

  it("policyReadsJavaKeyring", (ctx) => {
    // ./run test generates a Java keyring and names it here, so under ./run test this check runs or fails, never skips.
    const named = process.env.PAZTPORT_JAVA_KEYRING;
    const p = named ?? join(repoRoot(), "poc-demos/java-mesh/out/keys/keyring.json");
    if (named === undefined && !existsSync(p)) ctx.skip();
    const ring = readKeyring(p);
    expect(typeof ring.policy).toBe("string");
    expect(Object.keys(ring.services).length).toBeGreaterThan(0);
    expect(readFileSync(p, "utf8")).toContain("services");
    // Only the generated keyring is signed; an old local demo keyring is not, and must not fail a local run.
    if (named !== undefined) expect(verifyKeyring(ring as SignedKeyring, ring.policy)).toBe(true);
  });

  /** Keys for gateway and orders plus a paths.yaml, for the reply certificate cases. */
  function certWorld(): { keys: string; yamlPath: string; policyArgs: (out: string, ...extra: string[]) => string[] } {
    const keys = tmp();
    expect(run(keygen, ["--out", keys, "--services", "gateway,orders"]).status).toBe(0);
    const yamlPath = join(keys, "paths.yaml");
    writeFileSync(yamlPath, "paths:\n  - [gateway, orders]\n");
    const policyArgs = (out: string, ...extra: string[]) => ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--out", out, ...extra];
    return { keys, yamlPath, policyArgs };
  }

  it("policyIssuesAReplyCertForTheKeyringsKey", () => {
    const { keys, policyArgs } = certWorld();
    const out = tmp();
    const before = Date.now();
    const r = run(policy, policyArgs(out, "--reply-cert-svc", "orders", "--keyring", join(keys, "keyring.json"), "--reply-cert-days", "30"));
    const after = Date.now();
    expect(r.status, r.stderr).toBe(0);
    const ring = readKeyring(join(keys, "keyring.json"));
    const cert = readJson<ReplyCert>(join(out, "reply-cert.json"));
    expect(Object.keys(cert)).toEqual(["policy", "svc", "key", "notAfter", "sig"]);
    expect(verifyReplyCert(cert, ring.policy)).toBe(true);
    expect(cert.svc).toBe("orders");
    expect(cert.key).toBe(ring.services.orders);
    const day = 86_400_000;
    expect(cert.notAfter).toBeGreaterThanOrEqual(before + 30 * day);
    expect(cert.notAfter).toBeLessThanOrEqual(after + 30 * day);
    expect(existsSync(join(out, "root.json"))).toBe(true);
    // Only the service and notAfter are printed, never key material.
    expect(r.stdout).toContain("orders");
    expect(r.stdout).toContain(String(cert.notAfter));
    for (const secret of [ring.policy, ring.services.orders!, cert.sig, readKey(join(keys, "policy.key"))]) {
      expect(r.stdout + r.stderr).not.toContain(secret);
    }
  });

  it("policyReplyCertDefaultsToSevenDays", () => {
    const { keys, policyArgs } = certWorld();
    const out = tmp();
    const before = Date.now();
    expect(run(policy, policyArgs(out, "--reply-cert-svc", "orders", "--keyring", join(keys, "keyring.json"))).status).toBe(0);
    const cert = readJson<ReplyCert>(join(out, "reply-cert.json"));
    expect(cert.notAfter - before).toBeGreaterThanOrEqual(7 * 86_400_000);
    expect(cert.notAfter - before).toBeLessThan(7 * 86_400_000 + 60_000);
  });

  it("policyWritesNoReplyCertUnlessAsked", () => {
    const { policyArgs } = certWorld();
    const out = tmp();
    expect(run(policy, policyArgs(out)).status).toBe(0);
    expect(existsSync(join(out, "reply-cert.json"))).toBe(false);
  });

  it("policyRefusesAKeyringThatDoesNotVerify", () => {
    const { keys, policyArgs } = certWorld();
    const ring = readKeyring(join(keys, "keyring.json"));
    const cases: Record<string, unknown> = {
      tampered: { ...ring, services: { ...ring.services, orders: ring.services.gateway } },
      unsigned: { services: ring.services, policy: ring.policy },
      "bad signature": { ...ring, sig: "!" },
      "window moved": { ...ring, notAfter: ring.notAfter! + 1 },
      "window dropped": { services: ring.services, policy: ring.policy, sig: ring.sig },
      "window not an integer": { ...ring, notAfter: 1.5 },
    };
    for (const [name, bad] of Object.entries(cases)) {
      const path = join(tmp(), "keyring.json");
      writeFileSync(path, JSON.stringify(bad));
      const out = tmp();
      const r = run(policy, policyArgs(out, "--reply-cert-svc", "orders", "--keyring", path));
      expect(r.status, name).not.toBe(0);
      expect(r.stderr, name).toContain("keyring");
      expect(readdirSync(out), name).toEqual([]);
    }
  });

  it("policyStillCertifiesFromAnOldFormKeyring", () => {
    // nothing is refused for being in the old form yet
    const { keys, policyArgs } = certWorld();
    const ring = readKeyring(join(keys, "keyring.json"));
    const path = join(tmp(), "keyring.json");
    writeFileSync(path, JSON.stringify(signKeyringOldForm(ring.services, ring.policy, readKey(join(keys, "policy.key")))));
    const out = tmp();
    const r = run(policy, policyArgs(out, "--reply-cert-svc", "orders", "--keyring", path));
    expect(r.status, r.stderr).toBe(0);
    expect(verifyReplyCert(readJson<ReplyCert>(join(out, "reply-cert.json")), ring.policy)).toBe(true);
  });

  it("policyRefusesAKeyringOfAnotherPolicyKey", () => {
    const { policyArgs } = certWorld();
    const { keys: otherKeys } = certWorld();
    const out = tmp();
    const r = run(policy, policyArgs(out, "--reply-cert-svc", "orders", "--keyring", join(otherKeys, "keyring.json")));
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("policy key");
    expect(readdirSync(out)).toEqual([]);
  });

  it("policyRefusesAServiceTheKeyringLacks", () => {
    const { keys, policyArgs } = certWorld();
    // Names every plain object inherits are not services either.
    for (const svc of ["payment", "constructor", "__proto__", "toString"]) {
      const out = tmp();
      const r = run(policy, policyArgs(out, "--reply-cert-svc", svc, "--keyring", join(keys, "keyring.json")));
      expect(r.status, svc).not.toBe(0);
      expect(r.stderr, svc).toContain("no key for service");
      expect(readdirSync(out), svc).toEqual([]);
    }
  });

  it("policyReplyCertBadArgsExitNonZero", () => {
    const { keys, policyArgs } = certWorld();
    const ring = join(keys, "keyring.json");
    for (const extra of [
      ["--reply-cert-svc", "orders"],
      ["--keyring", ring],
      ["--reply-cert-days", "7"],
      ["--keyring", ring, "--reply-cert-days", "7"],
      ["--reply-cert-svc", "orders", "--keyring", ring, "--reply-cert-days", "0"],
      ["--reply-cert-svc", "orders", "--keyring", ring, "--reply-cert-days", "1.5"],
      ["--reply-cert-svc", "orders", "--keyring", ring, "--reply-cert-days", "x"],
      ["--reply-cert-svc", "orders", "--keyring", ring, "--reply-cert-days", "-1"],
      ["--reply-cert-svc", "orders", "--keyring", ring, "--reply-cert-days", "1e300"],
    ]) {
      const out = tmp();
      const r = run(policy, policyArgs(out, ...extra));
      expect(r.status, extra.join(" ")).toBe(2);
      expect(r.stderr, extra.join(" ")).toContain("Usage");
      expect(readdirSync(out), extra.join(" ")).toEqual([]);
    }
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
