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
      "and that the evidence agrees with the events log, the outcome log and the server key the run recorded (an older run recorded none).",
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

  it("activity trail: the current state on top with its seconds, the two before it below, frozen", async () => {
    const { pushActivity, trailLines } = await lib();
    let t: unknown[] = [];
    t = pushActivity(t, { state: "starting", label: "Starting pi and the mock GitHub server…", since: 0 }, 0);
    t = pushActivity(t, { state: "thinking", label: "The model is thinking…", since: 400 }, 400);
    expect(trailLines(t, 30_400)).toEqual(["The model is thinking… (30 s)", "Starting pi and the mock GitHub server"]);
    t = pushActivity(t, { state: "calling", label: "Calling: read README.md in acme/payroll-notes…", since: 41_400 }, 41_400);
    t = pushActivity(t, { state: "waiting", label: "Waiting for the mock GitHub server's reply…", since: 41_500 }, 41_500);
    // at most three entries; an entry that lasted under a second has no time, a longer one keeps the time it had
    expect(t).toHaveLength(3);
    expect(trailLines(t, 43_500)).toEqual([
      "Waiting for the mock GitHub server's reply… (2 s)",
      "Calling: read README.md in acme/payroll-notes",
      "The model is thinking (41 s)",
    ]);
    // the same event again (a reconnect replaying the latest) changes nothing
    expect(pushActivity(t, { state: "waiting", label: "Waiting for the mock GitHub server's reply…", since: 41_500 }, 50_000)).toBe(t);
    // a finished or stopped run has no seconds on top
    expect(trailLines(pushActivity(t, { state: "finished", label: "Run finished", since: 44_000 }, 44_000), 99_000)[0]).toBe("Run finished");
    expect(trailLines(pushActivity(t, { state: "stopped", label: "Run stopped", since: 44_000 }, 44_000), 99_000)[0]).toBe("Run stopped");
    // anything malformed is left out
    expect(pushActivity(t, { state: "thinking", label: 3 }, 0)).toBe(t);
    expect(pushActivity(t, undefined, 0)).toBe(t);
    expect(trailLines([], 0)).toEqual([]);
  });

  it("activity trail in a series: the place in the series is only on the top line, and a new run starts a new trail", async () => {
    const { pushActivity, trailLines } = await lib();
    const where1 = "Run 1 of 2 · Paztport on, run 1";
    const where2 = "Run 2 of 2 · Paztport on, run 2";
    let t: unknown[] = [];
    t = pushActivity(t, { state: "starting", label: "Starting pi and the mock GitHub server…", since: 0, where: where1 }, 0);
    t = pushActivity(t, { state: "thinking", label: "The model is thinking…", since: 5_000, where: where1 }, 5_000);
    expect(trailLines(t, 8_000)).toEqual([`${where1} — The model is thinking… (3 s)`, "Starting pi and the mock GitHub server (5 s)"]);
    t = pushActivity(t, { state: "finished", label: "Run finished", since: 9_000, where: where1 }, 9_000);
    t = pushActivity(t, { state: "starting", label: "Starting pi and the mock GitHub server…", since: 9_100, where: where2 }, 9_100);
    expect(trailLines(t, 10_000)).toEqual([`${where2} — Starting pi and the mock GitHub server… (1 s)`]);
  });

  it("activityView: the trail's elements are plain text with no live region or role, and a fainter style below the top", async () => {
    const { activityView, pushActivity } = await lib();
    type El = { tag: string; props: Record<string, unknown>; kids: El[]; textContent: string; hidden: boolean };
    const made: El[] = [];
    const h = (tag: string, props: Record<string, unknown>, ...kids: El[]): El => {
      const el = { tag, props, kids, textContent: "", hidden: props.hidden === true };
      made.push(el);
      return el;
    };
    const view = activityView(h);
    expect(made.length).toBeGreaterThan(1);
    for (const el of made) {
      expect(Object.keys(el.props)).not.toContain("aria-live");
      expect(Object.keys(el.props)).not.toContain("role");
      expect(Object.keys(el.props).some((k) => k.startsWith("on"))).toBe(false);
    }
    expect(view.root.hidden).toBe(true);
    expect(view.lines).toHaveLength(3);
    expect(view.lines[0].props.class).toBe("activity-line");
    expect(view.lines.slice(1).every((l: El) => l.props.class === "activity-line past")).toBe(true);
    let t: unknown[] = [];
    t = pushActivity(t, { state: "starting", label: "Starting pi and the mock GitHub server…", since: 0 }, 0);
    t = pushActivity(t, { state: "thinking", label: "The model is thinking…", since: 2_000 }, 2_000);
    view.render(t, 40_000);
    expect(view.root.hidden).toBe(false);
    expect(view.lines.map((l: El) => [l.textContent, l.hidden])).toEqual([
      ["The model is thinking… (38 s)", false],
      ["Starting pi and the mock GitHub server (2 s)", false],
      ["", true],
    ]);
    view.render([], 0);
    expect(view.root.hidden).toBe(true);
  });

  it("tallyLine: the classes so far, with the same names as the summary", async () => {
    const { tallyLine } = await lib();
    expect(tallyLine({ leaked: 2, blocked: 0, resisted: 7, other: 1 })).toBe("So far: leaked 2, blocked 0, resisted 7, other 1 (timeout, error or no tool calls).");
    expect(tallyLine(undefined)).toBe("");
    expect(tallyLine({ leaked: "x" })).toBe("");
  });

  it("the page builds the activity trail with activityView and feeds it activity events", () => {
    const app = text("app.js");
    expect(app).toMatch(/event === "activity"/);
    expect(app).toContain("activityView(h)");
    expect(app).toContain("pushActivity(");
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

  it("the off choice and the note for the local-tools scenario: elements exist, text comes from the server, compare is guarded", () => {
    const html = text("index.html");
    expect(html).toMatch(/id="mode-off"/);
    expect(html).toMatch(/id="off-note"[^>]*hidden/);
    const app = text("app.js");
    // hidden unless the server says the flag was given, and for a scenario the server marks as having local tools
    expect(app).toContain("unsafeToolUsage !== true");
    expect(app).toContain("scenario?.localTools === true");
    expect(app).toContain("state.setup?.offModeNote");
    expect(app).toMatch(/!offHidden\(scenarioById\(settings\.scenario\)\)/);
    // the copy is the server's (the runner's OFF_MODE_COPY), never retyped on the page
    expect(app).not.toContain("--unsafe-tool-usage");
    expect(app).not.toContain("real shell on this machine");
  });

  it("the page asks the server for the local wording: definitions, limits and classes note are chosen by the scenario", () => {
    const app = text("app.js");
    expect(app).toContain("localDefinitions");
    expect(app).toContain("localClassesNote");
    expect(app).toContain("localLimits");
    expect(app).not.toContain("Classes come from the mock server's outcome log, the extension's events log");
    // every place a table, a definition or the limits are shown goes through the choice
    expect(app).not.toMatch(/state\.setup\?\.table\?\.(definitions|limits)\b/);
  });

  it("the drawer for a local row shows the rule, the local chain and the route proof, and none of the MCP-only sections", () => {
    const app = text("app.js");
    expect(app).toContain("function localSections");
    for (const heading of ["What was checked", "Route proof", "Signed local chain"]) expect(app, heading).toContain(heading);
    expect(app).toContain("if (!step.local) sections.push(");
    expect(app).toContain("!step.local && (attested || reply)");
  });

  it("the drawer reads each record's decoded tokens, and says when one did not read", () => {
    const app = text("app.js");
    for (const read of ["call?.display?.chain", "reply?.display?.attestation", "record?.display?.chain", "record?.display?.influence", "record?.display?.proof"]) {
      expect(app, read).toContain(read);
    }
    expect(app).toContain("function unreadable(record, name)");
    for (const check of ['unreadable(call, "paztport/chain")', 'unreadable(reply, "paztport/attestation")', 'unreadable(record, "chain")', 'unreadable(record, "influence")', 'unreadable(record, "proof")']) {
      expect(app, check).toContain(check);
    }
  });

  it("an off run's local drawer says nothing was checked, and a local run's score names all three sources", () => {
    const app = text("app.js");
    expect(app).toContain("Paztport was off, so nothing was checked.");
    expect(app).toContain("localSections(step, local, plain, attested)");
    expect(app).toContain("Scored from the mock server's outcome log, the extension's events log and the workspace's public folders: ");
    expect(app).toContain("Scored from the mock server's outcome log: ");
  });

  it("a run in which Paztport refused to start says so before anything else", () => {
    const app = text("app.js");
    expect(app).toContain("Paztport did not start (");
    expect(app).toMatch(/function statusText\(d\) \{\s*return refusedStartText\(d\.refusedStart\) \+ runStatusText\(d\);/);
  });

  it("the setup carries the local wording the page uses", async () => {
    const { startDemoServer: start } = await import("../src/server.ts");
    const local = await start({
      resultsRoot: join(tmp, "results"),
      demoDir: join(tmp, "demo-keys"),
      scenarioDir: join(import.meta.dirname, "../../scenarios"),
      key: KEY,
      deps: { fetch: (async () => new Response(JSON.stringify({ models: [] }), { status: 200 })) as unknown as typeof fetch },
    });
    try {
      const setup = await (await fetch(`${local.url}/api/setup`, { headers: { "x-demo-key": KEY } })).json();
      expect(setup.scenarios.find((x: any) => x.id === "github-issue-replay-local").localTools).toBe(true);
      expect(setup.offModeNote).toMatch(/--unsafe-tool-usage/);
      expect(setup.table.localClassesNote).not.toBe(setup.table.classesNote);
    } finally {
      await local.close();
    }
  });
});
