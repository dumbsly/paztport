// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { OFF_MODE_COPY } from "../../eval/src/runner.ts";
import { BUILTIN_SCENARIO_DIR } from "../../mock-github-mcp/src/scenario.ts";
import { keysComplete, launch, nodeAtLeast, type LaunchDeps, type Launched } from "../src/main.ts";

/** The text of a keyring, root or reply certificate file `file`, with its window `notAfter` (left out if undefined). */
function windowed(file: string, notAfter?: unknown): string {
  const window = notAfter === undefined ? {} : { notAfter };
  if (file.endsWith("keyring.json")) return JSON.stringify({ policy: "p", services: {}, sig: "s", ...window });
  if (file.endsWith("root.json")) return JSON.stringify({ root: "r", rootId: "v", sig: "s", ...window });
  return JSON.stringify({ key: "k", policy: "p", sig: "s", svc: "orders", ...window });
}

let tmp: string;
let n = 0;
const open: Launched[] = [];
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-demo-main-"));
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
afterEach(async () => {
  while (open.length) await open.pop()!.close();
});

const up = (async () => new Response(JSON.stringify({ models: [{ name: "qwen3:4b" }] }), { status: 200 })) as unknown as typeof fetch;
const down = (async () => {
  throw new Error("ECONNREFUSED");
}) as unknown as typeof fetch;

function deps(over: Partial<LaunchDeps> = {}) {
  const logs: string[] = [];
  const opened: string[] = [];
  const keysFor: string[] = [];
  const d: LaunchDeps = {
    fetch: up,
    log: (s) => void logs.push(s),
    opener: (url) => void opened.push(url),
    ensureKeys: (dir) => void keysFor.push(dir),
    paths: { demoRoot: join(tmp, `case-${n++}`), scenarioDir: BUILTIN_SCENARIO_DIR },
    nodeVersion: "22.19.0",
    ...over,
  };
  return { d, logs, opened, keysFor };
}

async function ok(argv: string[], d: LaunchDeps): Promise<Launched> {
  const r = await launch(argv, d);
  if ("exitCode" in r) throw new Error(`exited ${r.exitCode}`);
  open.push(r);
  return r;
}

describe("demo launcher", () => {
  it("compares Node versions against the floor", () => {
    expect(nodeAtLeast("22.19.0", "22.19")).toBe(true);
    expect(nodeAtLeast("22.18.9", "22.19")).toBe(false);
    expect(nodeAtLeast("24.0.0", "22.19")).toBe(true);
    expect(nodeAtLeast("21.9.0", "22.19")).toBe(false);
  });

  it("demo keys without the local-tools policy are not complete", () => {
    // a local-tools run points the extension at client/local-tools, and the extension refuses to start without it
    const dir = mkdtempSync(join(tmpdir(), "demo-keys-"));
    try {
      for (const f of ["client/root.json", "client/server-policy.pub", "server/root.json", "client/keyring.json", "server/keyring.json"]) {
        mkdirSync(join(dir, f, ".."), { recursive: true });
        writeFileSync(join(dir, f), windowed(f, Date.now() + 2 * 86_400_000));
      }
      writeFileSync(join(dir, "server/reply-cert.json"), windowed("reply-cert.json", Date.now() + 2 * 86_400_000));
      expect(keysComplete(dir)).toBe(false);
      mkdirSync(join(dir, "client/local-tools"), { recursive: true });
      writeFileSync(join(dir, "client/local-tools/rules.json"), "{}");
      writeFileSync(join(dir, "client/local-tools/root.json"), windowed("root.json", Date.now() + 2 * 86_400_000));
      expect(keysComplete(dir)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("demo keys without a reply certificate current for a day are not complete", () => {
    // the mock server refuses to start without a current one, so keys with none, or a month old, are made again;
    // and evidence saved near notAfter would fail verify later, so a day short of it they are made again too
    const dir = mkdtempSync(join(tmpdir(), "demo-keys-"));
    try {
      for (const f of ["client/root.json", "client/server-policy.pub", "client/local-tools/rules.json", "client/local-tools/root.json", "server/root.json", "client/keyring.json", "server/keyring.json"]) {
        mkdirSync(join(dir, f, ".."), { recursive: true });
        writeFileSync(join(dir, f), windowed(f, Date.now() + 2 * 86_400_000));
      }
      const cert = join(dir, "server/reply-cert.json");
      expect(keysComplete(dir)).toBe(false);
      const day = 86_400_000;
      for (const notAfter of ["later", Date.now() - 1, Date.now() + 60_000, Date.now() + day - 60_000]) {
        for (const text of ["", "{}", windowed("reply-cert.json", notAfter)]) {
          writeFileSync(cert, text);
          expect(keysComplete(dir), text).toBe(false);
        }
      }
      writeFileSync(cert, windowed("reply-cert.json", Date.now() + day + 60_000));
      expect(keysComplete(dir)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("demo keys with less than a day left on any one keyring, root or the certificate are not complete", () => {
    const dir = mkdtempSync(join(tmpdir(), "demo-keys-"));
    const day = 86_400_000;
    const files = ["server/keyring.json", "server/root.json", "client/keyring.json", "client/root.json", "client/local-tools/root.json", "server/reply-cert.json"];
    const write = (f: string, notAfter: unknown) => {
      mkdirSync(join(dir, f, ".."), { recursive: true });
      writeFileSync(join(dir, f), f.endsWith(".json") && !f.endsWith("rules.json") ? windowed(f, notAfter) : "");
    };
    try {
      for (const f of ["client/server-policy.pub", "client/local-tools/rules.json"]) write(f, undefined);
      const fresh = () => files.forEach((f) => write(f, Date.now() + 2 * day));
      fresh();
      expect(keysComplete(dir)).toBe(true);
      for (const f of files) {
        for (const notAfter of [Date.now() + day - 60_000, Date.now() - 1, undefined, "later"]) {
          fresh();
          write(f, notAfter);
          expect(keysComplete(dir), `${f} ${String(notAfter)}`).toBe(false);
        }
      }
      fresh();
      rmSync(join(dir, "client/keyring.json"));
      expect(keysComplete(dir)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an old Node is one plain message and nothing starts", async () => {
    const { d, logs, opened } = deps({ nodeVersion: "20.1.0" });
    const r = await launch([], d);
    expect(r).toEqual({ exitCode: 2 });
    expect(logs.join("\n")).toMatch(/Node 22\.19 or newer/);
    expect(opened).toEqual([]);
  });

  it("Ollama not running is one plain message, unless the user brought their own agent dir", async () => {
    const a = deps({ fetch: down });
    expect(await launch([], a.d)).toEqual({ exitCode: 1 });
    expect(a.logs.join("\n")).toMatch(/Ollama isn't reachable at 127\.0\.0\.1:11434\. Start it with `ollama serve`/);
    expect(a.opened).toEqual([]);
    const b = deps({ fetch: down });
    mkdirSync(join(tmp, "mine"), { recursive: true });
    const started = await ok(["--agent-dir", join(tmp, "mine"), "--no-open"], b.d);
    expect(started.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/#key=/);
  });

  it("starts the server on loopback, prints the keyed address and opens it", async () => {
    const { d, logs, opened, keysFor } = deps();
    const r = await ok([], d);
    const u = new URL(r.url);
    expect(u.hostname).toBe("127.0.0.1");
    const key = /^#key=([A-Za-z0-9_-]{43})$/.exec(u.hash)?.[1];
    expect(key).toBeDefined();
    expect(opened).toEqual([r.url]);
    expect(logs.join("\n")).toContain(r.url);
    expect(keysFor).toEqual([join(d.paths!.demoRoot, "demo-keys")]);
    const base = `${u.protocol}//${u.host}`;
    expect((await fetch(`${base}/api/setup`)).status).toBe(403);
    const setup = await fetch(`${base}/api/setup`, { headers: { "x-demo-key": key! } });
    expect(setup.status).toBe(200);
  });

  it("--no-open prints the address and opens nothing; a fresh key each launch", async () => {
    const a = deps();
    const b = deps();
    const ra = await ok(["--no-open"], a.d);
    const rb = await ok(["--no-open"], b.d);
    expect(a.opened).toEqual([]);
    expect(new URL(ra.url).hash).not.toBe(new URL(rb.url).hash);
  });

  it("--results opens a published folder, and a missing folder is a usage error", async () => {
    const published = join(tmp, "published");
    mkdirSync(published, { recursive: true });
    const r = await ok(["--results", published, "--no-open"], deps().d);
    const u = new URL(r.url);
    const list = await (await fetch(`${u.protocol}//${u.host}/api/results`, { headers: { "x-demo-key": /key=(.*)/.exec(u.hash)![1]! } })).json();
    expect(list.map((e: any) => e.name)).toEqual(["published"]);
    const bad = deps();
    expect(await launch(["--results", join(tmp, "nope")], bad.d)).toEqual({ exitCode: 2 });
    expect(bad.logs.join("\n")).toMatch(/isn't a folder/);
    expect(await launch(["--bogus"], deps().d)).toEqual({ exitCode: 2 });
  });

  it("--agent-dir that isn't a folder is a plain usage error and nothing starts", async () => {
    const bad = deps();
    expect(await launch(["--agent-dir", join(tmp, "no-such-agent-dir")], bad.d)).toEqual({ exitCode: 2 });
    expect(bad.logs.join("\n")).toMatch(/no-such-agent-dir isn't a folder/);
    expect(bad.opened).toEqual([]);
    expect(bad.keysFor).toEqual([]);
  });

  it("--unsafe-tool-usage reaches the server: without it the local-tools scenario is on-only, with it the choice is offered", async () => {
    const scenarios = join(import.meta.dirname, "../../scenarios");
    // a run is only ever started where it is refused: the launcher here has no stub runner
    const get = async (argv: string[], tryOff: boolean) => {
      const { d, logs } = deps({ paths: { demoRoot: join(tmp, `case-${n++}`), scenarioDir: scenarios } });
      const r = await ok(argv, d);
      const u = new URL(r.url);
      const headers = { "x-demo-key": /key=(.*)/.exec(u.hash)![1]! };
      const setup = await (await fetch(`${u.protocol}//${u.host}/api/setup`, { headers })).json();
      const off = tryOff
        ? await fetch(`${u.protocol}//${u.host}/api/runs`, {
            method: "POST",
            headers: { ...headers, "content-type": "application/json" },
            body: JSON.stringify({ model: "ollama/qwen3:4b", scenario: "github-issue-replay-local", mode: "off", runs: 1 }),
          })
        : undefined;
      return { setup, off, logs };
    };
    const without = await get(["--no-open"], true);
    expect(without.setup.unsafeToolUsage).toBe(false);
    expect(without.setup.scenarios.map((s: any) => [s.id, s.localTools === true])).toEqual([
      ["github-issue-replay", false],
      ["github-issue-replay-local", true],
    ]);
    expect(without.off!.status).toBe(400);
    expect((await without.off!.json()).error).toBe(OFF_MODE_COPY);
    const flagged = await get(["--no-open", "--unsafe-tool-usage"], false);
    expect(flagged.setup.unsafeToolUsage).toBe(true);
    expect(flagged.logs.join("\n")).toMatch(/--unsafe-tool-usage.*only in a sandbox/);
    expect(without.logs.join("\n")).not.toMatch(/unsafe-tool-usage/);
  });
});
