// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cell } from "../../eval/src/report.ts";
import { wilson } from "../../eval/src/score.ts";
import { BUILTIN_SCENARIO_DIR } from "../../mock-github-mcp/src/scenario.ts";
import { startDemoServer, type DemoServer } from "../src/server.ts";

const PUBLIC = join(import.meta.dirname, "../public");
const KEY = "page-test-key-0123456789";
const files = () => readdirSync(PUBLIC).filter((f) => !f.startsWith("."));
const text = (f: string) => readFileSync(join(PUBLIC, f), "utf8");
const all = () => files().map((f) => ({ f, t: text(f) }));

let tmp: string;
let srv: DemoServer;
beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-page-"));
  mkdirSync(join(tmp, "results"), { recursive: true });
  srv = await startDemoServer({
    resultsRoot: join(tmp, "results"),
    demoDir: join(tmp, "demo-keys"),
    scenarioDir: BUILTIN_SCENARIO_DIR,
    key: KEY,
    deps: {
      fetch: (async () => new Response(JSON.stringify({ models: [{ name: "qwen3:4b" }] }), { status: 200 })) as unknown as typeof fetch,
      runOnce: async (spec) => ({ status: "completed", exitCode: 0, durationMs: 1, canary: "c", mode: spec.mode }),
    },
  });
});
afterAll(async () => {
  await srv.close();
  rmSync(tmp, { recursive: true, force: true });
});

/** The page's helper module, loaded as the browser loads it. */
async function lib(): Promise<any> {
  return import(pathToFileURL(join(PUBLIC, "lib.js")).href);
}

describe("demo page", () => {
  it("servesPageWithKeyFromHash: index.html loads app.js, and app.js sends the key from the address", async () => {
    const page = await fetch(`${srv.url}/`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toMatch(/<script type="module" src="app\.js"><\/script>/);
    expect(html).toMatch(/<link rel="stylesheet" href="app\.css">/);
    const app = await fetch(`${srv.url}/app.js`);
    expect(app.status).toBe(200);
    expect(app.headers.get("content-type")).toMatch(/javascript/);
    const js = await app.text();
    expect(js).toContain("x-demo-key");
    expect(js).toContain("location.hash");
    expect(js).toMatch(/from "\.\/lib\.js"/);
    expect((await fetch(`${srv.url}/lib.js`)).status).toBe(200);
    expect((await fetch(`${srv.url}/app.css`)).status).toBe(200);
    // the page itself carries no key; the API refuses a request without one
    expect(html).not.toContain(KEY);
    expect((await fetch(`${srv.url}/api/setup`)).status).toBe(403);
  });

  it("noExternalUrls: nothing in public/ points off this machine", () => {
    for (const { f, t } of all()) {
      expect(t, f).not.toMatch(/https?:\/\//i);
      expect(t, f).not.toMatch(/(src|href)\s*=\s*["']?\/\//i);
      expect(t, f).not.toMatch(/url\(\s*["']?\/\//i);
      expect(t, f).not.toMatch(/@import/i);
    }
  });

  it("copyHasNoBannedWords", () => {
    const banned = ["catastrophic", "devastating", "nightmare", "terrifying", "zero-day", "military-grade", "bulletproof", "unhackable", "revolutionary"];
    for (const { f, t } of all()) {
      const lower = t.toLowerCase();
      for (const w of banned) expect(lower.includes(w), `${f} contains "${w}"`).toBe(false);
    }
  });

  it("never writes HTML from strings: model text, tool arguments and results go in as text", () => {
    for (const { f, t } of all().filter((x) => x.f.endsWith(".js"))) {
      expect(t, f).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    }
  });

  it("the page works under default-src 'self': no inline script or style", () => {
    const html = text("index.html");
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
    expect(html).not.toMatch(/<style|\sstyle=|\son[a-z]+=/i);
    expect(text("app.js")).not.toMatch(/setAttribute\(\s*["']style|["']style["']\s*:/);
  });

  it("every file carries the license header, and the styles have a dark scheme", () => {
    for (const { f, t } of all()) expect(t, f).toContain("SPDX-License-Identifier: Apache-2.0");
    expect(text("app.css")).toMatch(/prefers-color-scheme:\s*dark/);
  });

  it("the page carries the agreed wording", () => {
    const page = all()
      .map((x) => x.t)
      .join("\n");
    for (const s of [
      "Agent asked to…",
      "Its context already held",
      "Result",
      "Run the same prompt with Paztport off",
      "These are two separate model runs; the model may behave differently in each, and the off run may not leak at all.",
      "free, runs on this machine",
      "time depends on your hardware",
      "uses your provider account; check its terms",
      "not recorded in this folder's format",
      "custom",
      "Server's reply",
      "For a folder it also checks that every run whose outcome log shows signed calls has signed evidence.",
      "The outcome log shows signed calls, but the evidence file has no signed records.",
      "nothing signed to check",
      "The page itself loads nothing from the internet",
      "results.json disagrees with the files",
      "Results (checked now)",
      "Checked now: ",
      "Recorded by the eval that wrote this folder.",
      "this page did those when you opened the folder",
    ]) {
      expect(page, s).toContain(s);
    }
  });

  it("keyFromHash reads the key from #key=…", async () => {
    const { keyFromHash } = await lib();
    expect(keyFromHash("#key=abc_DEF-123")).toBe("abc_DEF-123");
    expect(keyFromHash("#other=1&key=xyz")).toBe("xyz");
    expect(keyFromHash("")).toBeUndefined();
    expect(keyFromHash("#key=")).toBeUndefined();
  });

  it("sseParser: events split across chunks, CRLF, comments and several data lines", async () => {
    const { sseParser } = await lib();
    const p = sseParser();
    expect(p.feed(": connected\n\nevent: st")).toEqual([]);
    expect(p.feed('ep\ndata: {"index":1}\n\nevent: step\r\ndata: {"index":2}\r\n\r\n: ping\n\n')).toEqual([
      { event: "step", data: '{"index":1}' },
      { event: "step", data: '{"index":2}' },
    ]);
    expect(p.feed("data: a\ndata: b\n\n")).toEqual([{ event: "message", data: "a\nb" }]);
    // a chunk can end between the \r and \n of one line break
    expect(p.feed("data: x\r")).toEqual([]);
    expect(p.feed("\n\r\n")).toEqual([{ event: "message", data: "x" }]);
    expect(p.feed("event: done\ndata: {}")).toEqual([]);
    expect(p.end()).toEqual([{ event: "done", data: "{}" }]);
  });

  it("formatCell matches the results table in summary.md", async () => {
    const { formatCell } = await lib();
    for (const [k, n] of [
      [0, 0],
      [0, 1],
      [3, 20],
      [20, 20],
      [7, 13],
    ] as const) {
      const c = { k, n, ci: wilson(k, n) };
      expect(formatCell(c)).toBe(cell(c));
    }
    expect(formatCell(undefined)).toBe("not recorded in this folder's format");
  });

  it("the classes note is the report's own sentence, sent by the server, never a copy that can drift", () => {
    const app = text("app.js");
    expect(app).toContain("table?.classesNote");
    expect(app).not.toContain("Every class comes from");
  });

  it("formatDuration is short and plain", async () => {
    const { formatDuration } = await lib();
    expect(formatDuration(4_200)).toBe("4 s");
    expect(formatDuration(68_000)).toBe("1 min 8 s");
    expect(formatDuration(600_000)).toBe("10 min");
  });
});
