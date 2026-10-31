// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyKeyring, verifyReplyCert } from "@paztport/core";
import { loadClientMaterial } from "../../pi-extension/src/keys.ts";
import { loadServerConfig } from "../src/paztport.ts";
import { afterAll, describe, expect, it } from "vitest";

const SETUP = join(import.meta.dirname, "../../scripts/setup-demo.ts");
const tmp = mkdtempSync(join(tmpdir(), "paztport-setup-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const setup = (...args: string[]) => spawnSync(process.execPath, [SETUP, ...args], { encoding: "utf8" });
const serverPolicy = (out: string) => (JSON.parse(readFileSync(join(out, "server/keyring.json"), "utf8")) as { policy: string }).policy;
const pin = (out: string) => readFileSync(join(out, "client/server-policy.pub"), "utf8");
const clientPolicy = (out: string) => (JSON.parse(readFileSync(join(out, "client/keyring.json"), "utf8")) as { policy: string }).policy;
const clientPin = (out: string) => readFileSync(join(out, "server/client-policy.pub"), "utf8");

describe("setup-demo", () => {
  it("setupWritesServerPin", () => {
    const out = join(tmp, "pin");
    const r = setup("--out", out);
    expect(r.status, r.stderr).toBe(0);
    expect(pin(out)).toBe(serverPolicy(out) + "\n");
    expect(r.stdout).not.toContain(serverPolicy(out));
    // the server pins the client policy key it opens attested sessions for
    expect(clientPin(out)).toBe(clientPolicy(out) + "\n");
    expect(r.stdout).not.toContain(clientPolicy(out));
    // neither policy private key is kept: each only signs offline, at setup
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
    expect(existsSync(join(out, "server/policy.key"))).toBe(false);
  });

  it("serverPolicyKeyDeleted", () => {
    const out = join(tmp, "cert");
    const before = Date.now();
    const r = setup("--out", out);
    const after = Date.now();
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(join(out, "server/policy.key"))).toBe(false);
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
    // the root, keyring and certificate were all signed before the key went
    const serverPin = pin(out).trim();
    const ring = JSON.parse(readFileSync(join(out, "server/keyring.json"), "utf8"));
    expect(verifyKeyring(ring, serverPin)).toBe(true);
    const cert = JSON.parse(readFileSync(join(out, "server/reply-cert.json"), "utf8"));
    expect(verifyReplyCert(cert, serverPin)).toBe(true);
    expect(cert).toMatchObject({ policy: serverPin, svc: "mcp-entry", key: ring.services["mcp-entry"] });
    const DAYS_30 = 30 * 86_400_000;
    expect(cert.notAfter).toBeGreaterThanOrEqual(before + DAYS_30);
    expect(cert.notAfter).toBeLessThanOrEqual(after + DAYS_30);
    expect(r.stdout).not.toContain(cert.sig);
    // the server starts from what is left
    expect(loadServerConfig(join(out, "server")).replyCert).toEqual(cert);
  });

  it("setupWritesThirtyDayMaterialForBothSides", () => {
    const out = join(tmp, "thirty");
    const before = Date.now();
    const r = setup("--out", out);
    const after = Date.now();
    expect(r.status, r.stderr).toBe(0);
    const DAYS_30 = 30 * 86_400_000;
    const read = (f: string) => JSON.parse(readFileSync(join(out, f), "utf8")) as { notAfter?: number };
    for (const f of ["server/keyring.json", "server/root.json", "client/keyring.json", "client/root.json", "client/local-tools/root.json"]) {
      const { notAfter } = read(f);
      expect(notAfter, f).toBeGreaterThanOrEqual(before + DAYS_30);
      expect(notAfter, f).toBeLessThanOrEqual(after + DAYS_30);
    }
    // the client keyring is re-signed beside the local-tools root with the same window
    expect(verifyKeyring(read("client/keyring.json") as never, clientPolicy(out))).toBe(true);
  });

  it("setupBuildsLocalToolsPolicy", () => {
    const out = join(tmp, "local");
    const r = setup("--out", out);
    expect(r.status, r.stderr).toBe(0);
    const lt = join(out, "client/local-tools");
    for (const f of ["root.json", "proofs-pi.json", "rules.json"]) expect(existsSync(join(lt, f)), f).toBe(true);
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
    expect(existsSync(join(lt, "policy.key"))).toBe(false);
    // the base client root carries no rules route
    const base = loadClientMaterial(join(out, "client"));
    expect(Object.keys(base.proofs).some((k) => k.startsWith("session/pi/rules:"))).toBe(false);
    expect(base.rules).toBeUndefined();
    const m = loadClientMaterial(join(out, "client"), lt);
    expect(Object.keys(m.proofs).filter((k) => k.startsWith("session/pi/rules:"))).toHaveLength(1);
  });

  it("setupRefusesOverwriteWithoutForce", () => {
    const out = join(tmp, "again");
    expect(setup("--out", out).status).toBe(0);
    const before = serverPolicy(out);
    const refused = setup("--out", out);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toMatch(/already exists.*--force/);
    expect(serverPolicy(out)).toBe(before);
    const forced = setup("--out", out, "--force");
    expect(forced.status, forced.stderr).toBe(0);
    expect(serverPolicy(out)).not.toBe(before);
    expect(pin(out)).toBe(serverPolicy(out) + "\n");
    expect(clientPin(out)).toBe(clientPolicy(out) + "\n");
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
    expect(existsSync(join(out, "server/policy.key"))).toBe(false);
  });
});
