// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  decode, isCurrent, parseLocalRules, renewKeyring, signRenewedRoot, rulesHash, rulesRoute, sign, signKeyringOldForm, signRootOldForm, utf8, verify, verifyKeyring, verifyProof, verifyReplyCert, verifyRoot,
} from "@paztport/core";
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
      const r = run(policy, ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--keyring", join(keys, "keyring.json"), "--out", out]);
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
    const r = run(policy, ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--keyring", join(keys, "keyring.json"), "--out", out]);
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

  /** A paths.yaml with a `local:` block, for the client chain cases. */
  function localWorld(): { keys: string; args: (out: string, ...extra: string[]) => string[] } {
    const keys = tmp();
    expect(run(keygen, ["--out", keys, "--services", "origin,pi"]).status).toBe(0);
    const yamlPath = join(keys, "paths.yaml");
    writeFileSync(yamlPath, "paths:\n  - [origin, pi, \"mcp:github.list_issues\"]\nlocal:\n  folders:\n    - { path: \".\", access: [read] }\n  programs: []\n");
    return { keys, args: (out, ...extra) => ["--paths", yamlPath, "--policy-key", join(keys, "policy.key"), "--keyring", join(keys, "keyring.json"), "--out", out, ...extra] };
  }

  it("aLocalBlockNeedsTheClientChain", () => {
    const { args } = localWorld();
    const out = tmp();
    const r = run(policy, args(out));
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("--client-chain");
    expect(existsSync(join(out, "root.json"))).toBe(false);
  });

  it("theRulesRouteIsPinnedUnderTheClientChain", () => {
    const { args } = localWorld();
    const out = tmp();
    const r = run(policy, args(out, "--client-chain", "origin,pi"));
    expect(r.status, r.stderr).toBe(0);
    const rules = parseLocalRules(readJson<unknown>(join(out, "rules.json")));
    const bundle = readJson<{ proofs: Record<string, unknown> }>(join(out, "proofs-pi.json"));
    expect(Object.keys(bundle.proofs)).toContain(rulesRoute(["origin", "pi"], rulesHash(rules)));
  });

  it("aClientChainWithAnEmptyNodeIsRefused", () => {
    const { args } = localWorld();
    expect(run(policy, args(tmp(), "--client-chain", "origin,")).status).toBe(2);
  });

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
    const { keys, policyArgs } = certWorld();
    const out = tmp();
    expect(run(policy, policyArgs(out, "--keyring", join(keys, "keyring.json"))).status).toBe(0);
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

  /** Every file under `dirs`, by path, as its bytes and modification time: what "writes nothing" compares. */
  function snapshot(...dirs: string[]): Record<string, string> {
    const files: Record<string, string> = {};
    for (const d of dirs) {
      if (!existsSync(d)) continue;
      for (const f of readdirSync(d, { recursive: true, encoding: "utf8" })) {
        const p = join(d, f);
        if (statSync(p).isFile()) files[p] = `${readFileSync(p, "base64")}@${statSync(p).mtimeMs}`;
      }
    }
    return files;
  }

  it("keygenWritesNewFormKeyring", () => {
    const out = tmp();
    const before = Date.now();
    const r = run(keygen, ["--out", out, "--services", "a,b", "--policy-days", "30"]);
    const after = Date.now();
    expect(r.status, r.stderr).toBe(0);
    const ring = readKeyring(join(out, "keyring.json"));
    expect(ring.notAfter).toBeGreaterThanOrEqual(before + 30 * DAY_MS);
    expect(ring.notAfter).toBeLessThanOrEqual(after + 30 * DAY_MS);
    expect(verifyKeyring(ring as SignedKeyring, ring.policy)).toBe(true);
    expect(r.stdout).toContain(`notAfter ${ring.notAfter}`);
    // a lifetime past 2^53 - 1 ms is refused, as is anything but a positive whole number of days
    for (const bad of ["0", "-1", "1.5", "x", "", "1e300", "200000000"]) {
      const empty = tmp();
      const b = run(keygen, ["--out", empty, "--services", "a", "--policy-days", bad]);
      expect(b.status, bad).toBe(2);
      expect(b.stderr, bad).toContain("Usage");
      expect(readdirSync(empty), bad).toEqual([]);
    }
  });

  it("rebuildSignsRootAndKeyringWithLifetime", () => {
    const { keys, policyArgs } = certWorld();
    const before = readKeyring(join(keys, "keyring.json"));
    const out = tmp();
    const start = Date.now();
    const r = run(policy, policyArgs(out, "--keyring", join(keys, "keyring.json"), "--policy-days", "30"));
    const end = Date.now();
    expect(r.status, r.stderr).toBe(0);
    const root = readJson<SignedRoot>(join(out, "root.json"));
    const ring = readKeyring(join(keys, "keyring.json"));
    // both signed in the new form until the one notAfter
    expect(root.notAfter).toBeGreaterThanOrEqual(start + 30 * DAY_MS);
    expect(root.notAfter).toBeLessThanOrEqual(end + 30 * DAY_MS);
    expect(ring.notAfter).toBe(root.notAfter);
    expect(Object.keys(readJson<object>(join(keys, "keyring.json")))).toEqual(["services", "policy", "sig", "notAfter"]);
    expect(verifyRoot(root, before.policy)).toBe(true);
    expect(verifyKeyring(ring as SignedKeyring, before.policy)).toBe(true);
    expect(ring.services).toEqual(before.services);
    expect(ring.policy).toBe(before.policy);
    // only file names and notAfter are printed
    expect(r.stdout).toContain(join(keys, "keyring.json"));
    expect(r.stdout).toContain(join(out, "root.json"));
    expect(r.stdout).toContain(`notAfter ${root.notAfter}`);
    for (const secret of [ring.policy, ring.sig!, root.sig, root.root, readKey(join(keys, "policy.key"))]) {
      expect(r.stdout + r.stderr).not.toContain(secret);
    }
  });

  it("rebuildRefusesForeignKeyring", () => {
    const { keys, policyArgs } = certWorld();
    const { keys: otherKeys } = certWorld();
    const ring = readKeyring(join(keys, "keyring.json"));
    const cases: Record<string, unknown> = {
      "another policy key's": readKeyring(join(otherKeys, "keyring.json")),
      tampered: { ...ring, services: { ...ring.services, orders: ring.services.gateway } },
      unsigned: { services: ring.services, policy: ring.policy },
    };
    for (const [name, bad] of Object.entries(cases)) {
      writeFileSync(join(keys, "keyring.json"), JSON.stringify(bad));
      const out = tmp();
      const before = snapshot(keys);
      const r = run(policy, policyArgs(out, "--keyring", join(keys, "keyring.json")));
      expect(r.status, name).toBe(2);
      expect(r.stderr, name).toContain("refused");
      expect(r.stderr, name).toContain("keyring");
      expect(snapshot(keys), name).toEqual(before);
      expect(readdirSync(out), name).toEqual([]);
    }
    const out = tmp();
    const r = run(policy, policyArgs(out, "--keyring", join(keys, "missing.json")));
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("refused");
    expect(existsSync(join(keys, "missing.json"))).toBe(false);
    expect(readdirSync(out)).toEqual([]);
  });

  /** A built policy: keys, a root and bundles in `out`, all as the tools write them. */
  function builtWorld(...extra: string[]) {
    const world = certWorld();
    const out = tmp();
    const r = run(policy, world.policyArgs(out, "--keyring", join(world.keys, "keyring.json"), ...extra));
    expect(r.status, r.stderr).toBe(0);
    const renewArgs = (...more: string[]) => ["--renew", "--policy-key", join(world.keys, "policy.key"), "--keyring", join(world.keys, "keyring.json"), "--out", out, ...more];
    return { ...world, out, renewArgs };
  }

  it("renewKeepsTreeAndProofs", () => {
    const { keys, out, yamlPath, renewArgs } = builtWorld("--policy-days", "1");
    const built = readJson<SignedRoot>(join(out, "root.json"));
    const ringBefore = readKeyring(join(keys, "keyring.json"));
    const bundles = snapshot(out);
    delete bundles[join(out, "root.json")];
    // renewal reads no paths file: a narrowed one is not looked at
    writeFileSync(yamlPath, "paths:\n  - [orders, gateway]\n");
    const r = run(policy, renewArgs("--policy-days", "30", "--reply-cert-svc", "orders"));
    expect(r.status, r.stderr).toBe(0);
    const renewed = readJson<SignedRoot>(join(out, "root.json"));
    expect(renewed.rootId).toBe(built.rootId);
    expect(renewed.root).toBe(built.root);
    expect(renewed.notAfter).toBeGreaterThan(built.notAfter!);
    expect(Object.keys(renewed)).toEqual(["rootId", "root", "sig", "notAfter"]);
    expect(verifyRoot(renewed, ringBefore.policy)).toBe(true);
    // the bundles are untouched and still prove against the renewed root
    const after = snapshot(out);
    delete after[join(out, "root.json")];
    delete after[join(out, "reply-cert.json")];
    expect(after).toEqual(bundles);
    const bundle = readJson<ProofBundle>(join(out, "proofs-gateway.json"));
    expect(bundle.rootId).toBe(renewed.rootId);
    expect(verifyProof(bundle.proofs["gateway/orders"] as MerkleProof, "gateway/orders", decode(renewed.root))).toBe(true);
    // the keyring is renewed beside it, and the certificate reissued
    const ring = readKeyring(join(keys, "keyring.json"));
    expect(ring.notAfter).toBe(renewed.notAfter);
    expect(ring.services).toEqual(ringBefore.services);
    expect(verifyKeyring(ring as SignedKeyring, ringBefore.policy)).toBe(true);
    const cert = readJson<ReplyCert>(join(out, "reply-cert.json"));
    expect(verifyReplyCert(cert, ring.policy)).toBe(true);
    expect(cert.key).toBe(ring.services.orders);
    expect(r.stdout).toContain(`notAfter ${renewed.notAfter}`);
    expect(r.stdout).toContain(join(out, "root.json"));
    for (const secret of [ring.policy, ring.sig!, renewed.sig, renewed.root, cert.sig, readKey(join(keys, "policy.key"))]) {
      expect(r.stdout + r.stderr).not.toContain(secret);
    }
  });

  it("renewRefusesForeignRoot", () => {
    const { keys, out, renewArgs } = builtWorld();
    const { out: otherOut } = builtWorld();
    const built = readJson<SignedRoot>(join(out, "root.json"));
    const cases: Record<string, unknown> = {
      "another policy key's": readJson<SignedRoot>(join(otherOut, "root.json")),
      "window moved": { ...built, notAfter: built.notAfter! + 1 },
      "not a root": { rootId: built.rootId },
    };
    for (const [name, bad] of Object.entries(cases)) {
      writeFileSync(join(out, "root.json"), JSON.stringify(bad));
      const before = snapshot(keys, out);
      const r = run(policy, renewArgs("--reply-cert-svc", "orders"));
      expect(r.status, name).toBe(2);
      expect(r.stderr, name).toContain("refused");
      expect(r.stderr, name).toContain("root.json");
      expect(snapshot(keys, out), name).toEqual(before);
    }
  });

  it("renewRefusesForeignKeyring", () => {
    const { keys, out, renewArgs } = builtWorld();
    const { keys: otherKeys } = builtWorld();
    const ring = readKeyring(join(keys, "keyring.json"));
    const cases: Record<string, unknown> = {
      "another policy key's": readKeyring(join(otherKeys, "keyring.json")),
      tampered: { ...ring, services: { ...ring.services, orders: ring.services.gateway } },
      "window moved": { ...ring, notAfter: ring.notAfter! + 1 },
    };
    for (const [name, bad] of Object.entries(cases)) {
      writeFileSync(join(keys, "keyring.json"), JSON.stringify(bad));
      const before = snapshot(keys, out);
      const r = run(policy, renewArgs());
      expect(r.status, name).toBe(2);
      expect(r.stderr, name).toContain("refused");
      expect(r.stderr, name).toContain("keyring");
      expect(snapshot(keys, out), name).toEqual(before);
    }
  });

  it("renewAcceptsExpiredAndOldForm", () => {
    const { keys, out, renewArgs } = builtWorld();
    const built = readJson<SignedRoot>(join(out, "root.json"));
    const ring = readKeyring(join(keys, "keyring.json"));
    const priv = readKey(join(keys, "policy.key"));
    const expiredRoot = signRenewedRoot(built, 1000, priv);
    const oldRoot = signRootOldForm(decode(built.root), built.rootId, priv);
    const expiredRing = renewKeyring(ring as SignedKeyring, 1000, priv);
    const oldRing = signKeyringOldForm(ring.services, ring.policy, priv);
    for (const [name, root, keyring] of [["old root, expired keyring", oldRoot, expiredRing], ["expired root, old keyring", expiredRoot, oldRing]] as const) {
      writeFileSync(join(out, "root.json"), JSON.stringify(root));
      writeFileSync(join(keys, "keyring.json"), JSON.stringify(keyring));
      const r = run(policy, renewArgs());
      expect(r.status, `${name}: ${r.stderr}`).toBe(0);
      const now = Date.now();
      const renewed = readJson<SignedRoot>(join(out, "root.json"));
      expect(isCurrent(renewed, now), name).toBe(true);
      expect(renewed.rootId).toBe(built.rootId);
      expect(renewed.root).toBe(built.root);
      expect(verifyRoot(renewed, ring.policy), name).toBe(true);
      const renewedRing = readKeyring(join(keys, "keyring.json"));
      expect(isCurrent(renewedRing, now), name).toBe(true);
      expect(verifyKeyring(renewedRing as SignedKeyring, ring.policy), name).toBe(true);
    }
  });

  it("policyLifetimeAndModeBadArgsExitNonZero", () => {
    const { keys, yamlPath, out: built, renewArgs } = builtWorld();
    const ring = join(keys, "keyring.json");
    const key = join(keys, "policy.key");
    const rebuild = ["--paths", yamlPath, "--policy-key", key, "--keyring", ring];
    for (const args of [
      ["--paths", yamlPath, "--policy-key", key],
      [...rebuild, "--policy-days", "0"],
      [...rebuild, "--policy-days", "1.5"],
      [...rebuild, "--policy-days", "x"],
      [...rebuild, "--policy-days", "200000000"],
      ["--renew", "--policy-key", key],
      ["--renew", "--paths", yamlPath, "--policy-key", key, "--keyring", ring],
      ["--renew", "--depth", "8", "--policy-key", key, "--keyring", ring],
    ]) {
      const out = tmp();
      const before = snapshot(keys);
      const r = run(policy, [...args, "--out", out]);
      expect(r.status, args.join(" ")).toBe(2);
      expect(r.stderr, args.join(" ")).toContain("Usage");
      expect(readdirSync(out), args.join(" ")).toEqual([]);
      expect(snapshot(keys), args.join(" ")).toEqual(before);
    }
    const before = snapshot(keys, built);
    const r = run(policy, renewArgs("--policy-days", "0"));
    expect(r.status).toBe(2);
    expect(snapshot(keys, built)).toEqual(before);
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
