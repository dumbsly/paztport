// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const SETUP = join(import.meta.dirname, "../../scripts/setup-demo.ts");
const tmp = mkdtempSync(join(tmpdir(), "paztport-setup-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const setup = (...args: string[]) => spawnSync(process.execPath, [SETUP, ...args], { encoding: "utf8" });
const serverPolicy = (out: string) => (JSON.parse(readFileSync(join(out, "server/keyring.json"), "utf8")) as { policy: string }).policy;
const pin = (out: string) => readFileSync(join(out, "client/server-policy.pub"), "utf8");

describe("setup-demo", () => {
  it("setupWritesServerPin", () => {
    const out = join(tmp, "pin");
    const r = setup("--out", out);
    expect(r.status, r.stderr).toBe(0);
    expect(pin(out)).toBe(serverPolicy(out) + "\n");
    expect(r.stdout).not.toContain(serverPolicy(out));
    // the client policy private key only signs the client root; the server's signs session replies
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
    expect(existsSync(join(out, "server/policy.key"))).toBe(true);
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
    expect(existsSync(join(out, "client/policy.key"))).toBe(false);
  });
});
