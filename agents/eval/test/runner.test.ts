// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { BUILTIN_SCENARIO_DIR, loadScenario } from "../../mock-github-mcp/src/scenario.ts";
import { checkModelAvailable, parseModel, prepareAgentDir } from "../src/models.ts";
import { runOnce, type RunMode, type RunSpec } from "../src/runner.ts";

const STUB = join(import.meta.dirname, "fixtures/stub-pi.ts");
const MAIN = join(import.meta.dirname, "../../mock-github-mcp/src/main.ts");
const EXTENSION = join(import.meta.dirname, "../../pi-extension");
const KEYS = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "MISTRAL_API_KEY", "OPENROUTER_API_KEY"];
const OLLAMA = { provider: "ollama", id: "qwen3:4b" };

let tmp: string;
let demo: string;
let n = 0;

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "paztport-runner-"));
  demo = join(tmp, "demo");
  mkdirSync(join(demo, "client"), { recursive: true });
  mkdirSync(join(demo, "server"), { recursive: true });
  writeFileSync(join(demo, "client/pi.key"), "not a real key");
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
beforeEach(() => {
  vi.stubEnv("STUB_MARK", tmp);
  for (const k of KEYS) vi.stubEnv(k, "secret-" + k);
});
afterEach(() => {
  vi.unstubAllEnvs();
  // no process started by a test may outlive it
  const ps = execFileSync("ps", ["-axo", "command"], { encoding: "utf8" });
  const leaked = ps.split("\n").filter((l) => l.startsWith(`${process.execPath} `) && l.includes(tmp) && (l.includes("paztport-stub-grandchild") || l.includes("stub-pi.ts")));
  expect(leaked).toEqual([]);
});

type Case = { spec: RunSpec; record: string; pidfile: string };

function mk(over: Partial<RunSpec> = {}, behavior = "print"): Case {
  const i = n++;
  const record = join(tmp, `record-${i}.json`);
  const pidfile = join(tmp, `pid-${i}`);
  vi.stubEnv("STUB_BEHAVIOR", behavior);
  vi.stubEnv("STUB_RECORD", record);
  vi.stubEnv("STUB_PIDFILE", pidfile);
  const spec: RunSpec = {
    scenarioDir: BUILTIN_SCENARIO_DIR,
    mode: "on",
    model: OLLAMA,
    runDir: join(tmp, `run-${i}`),
    demoDir: demo,
    agentDir: join(tmp, `agent-${i}`),
    userAgentDir: false,
    timeoutMs: 20_000,
    piCli: STUB,
    ...over,
  };
  return { spec, record, pidfile };
}

const recorded = (c: Case) => JSON.parse(readFileSync(c.record, "utf8")) as { argv: string[]; env: Record<string, string>; cwd: string; listing: string[] };
const lines = (file: string) => readFileSync(file, "utf8").split("\n").filter(Boolean);
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
/** True once the process is gone; a killed process may linger as a zombie until its parent reaps it. */
async function gone(pid: number): Promise<boolean> {
  for (let i = 0; i < 40; i++) {
    if (!alive(pid)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}
const flagValue = (argv: string[], flag: string) => argv[argv.indexOf(flag) + 1];

describe("parseModel", () => {
  it("splits at the first slash", () => {
    expect(parseModel("ollama/qwen3:4b")).toEqual({ provider: "ollama", id: "qwen3:4b" });
    expect(parseModel("ollama/hf.co/a/b")).toEqual({ provider: "ollama", id: "hf.co/a/b" });
  });
  it("rejects a missing part", () => {
    for (const bad of ["qwen3", "/x", "ollama/", ""]) expect(() => parseModel(bad)).toThrow(/provider\/id/);
  });
});

describe("runOnce", () => {
  it("argsForEachMode", async () => {
    const scenario = loadScenario(BUILTIN_SCENARIO_DIR);
    const table: Record<RunMode, { ext: string; server: string; payload: string | null; warning: boolean }> = {
      off: { ext: "off", server: "off", payload: null, warning: false },
      on: { ext: "enforce", server: "enforce", payload: null, warning: false },
      "clean-off": { ext: "off", server: "off", payload: "none", warning: false },
      "clean-on": { ext: "enforce", server: "enforce", payload: "none", warning: false },
      warning: { ext: "off", server: "off", payload: null, warning: true },
    };
    for (const [mode, want] of Object.entries(table) as [RunMode, (typeof table)[RunMode]][]) {
      const warningFile = join(tmp, "warning.md");
      writeFileSync(warningFile, "Be careful.");
      const c = mk({ mode, ...(want.warning ? { warning: { file: warningFile } } : {}) });
      const r = await runOnce(c.spec);
      expect(r.status, mode).toBe("completed");
      expect(r.mode).toBe(mode);
      const { argv } = recorded(c);
      expect(argv[0], mode).toBe("-e");
      expect(argv[1]).toBe(EXTENSION);
      const configPath = flagValue(argv, "--paztport-config")!;
      expect(configPath).toBe(join(c.spec.runDir, "config.json"));
      expect(flagValue(argv, "--provider")).toBe("ollama");
      expect(flagValue(argv, "--model")).toBe("qwen3:4b");
      expect(flagValue(argv, "--tools")).toBe("mcp__github__*");
      expect(argv).toContain("--no-session");
      expect(flagValue(argv, "--mode")).toBe("json");
      // nothing outside the run folder reaches the model: no context files, skills, templates or user MCP config
      for (const f of ["--no-context-files", "--no-skills", "--no-prompt-templates", "--no-mcp", "--no-extensions"]) expect(argv, `${mode} ${f}`).toContain(f);
      expect(argv.at(-1)).toBe(scenario.userPrompt);
      expect(argv.at(-2)).toBe("--");
      if (want.warning) expect(flagValue(argv, "--append-system-prompt")).toBe(warningFile);
      else expect(argv).not.toContain("--append-system-prompt");

      const cfg = JSON.parse(readFileSync(configPath, "utf8"));
      expect(cfg.mode).toBe(want.ext);
      expect(cfg.clientDir).toBe(join(demo, "client"));
      expect(cfg.eventsLog).toBe(join(c.spec.runDir, "events.jsonl"));
      // without Paztport nothing is signed, so there is no evidence log and no evidence file
      if (want.ext === "off") {
        expect(cfg.evidenceLog, mode).toBeUndefined();
        expect(existsSync(join(c.spec.runDir, "evidence.jsonl")), mode).toBe(false);
      } else expect(cfg.evidenceLog, mode).toBe(join(c.spec.runDir, "evidence.jsonl"));
      expect(cfg.servers).toHaveLength(1);
      const server = cfg.servers[0];
      expect(server.id).toBe("github");
      expect(server.command).toBe(process.execPath);
      expect(server.attested).toBe(want.ext !== "off");
      expect(server.args[0]).toBe(MAIN);
      expect(flagValue(server.args, "--mode")).toBe(want.server);
      expect(flagValue(server.args, "--outcome-log")).toBe(join(c.spec.runDir, "outcome.jsonl"));
      expect(flagValue(server.args, "--scenario")).toBe(BUILTIN_SCENARIO_DIR);
      const canary = readFileSync(join(c.spec.runDir, "canary.txt"), "utf8").trim();
      expect(canary).toMatch(/^[0-9a-f]{16}$/);
      expect(flagValue(server.args, "--canary")).toBe(canary);
      if (want.payload === null) expect(server.args).not.toContain("--payload");
      else expect(flagValue(server.args, "--payload")).toBe(want.payload);
      if (want.server === "enforce") expect(flagValue(server.args, "--config")).toBe(join(demo, "server"));
      else expect(server.args).not.toContain("--config");
      expect(r.canary).toBe(canary);
    }
  });

  it("writes the run files and run.json", async () => {
    const c = mk();
    const r = await runOnce(c.spec);
    expect(r).toMatchObject({ status: "completed", exitCode: 0, mode: "on" });
    expect(r.durationMs).toBeGreaterThanOrEqual(0);
    expect(JSON.parse(readFileSync(join(c.spec.runDir, "run.json"), "utf8"))).toEqual(r);
    expect(lines(join(c.spec.runDir, "transcript.jsonl")).map((l) => JSON.parse(l).type)).toEqual(["session", "agent_end"]);
    expect(readFileSync(join(c.spec.runDir, "stderr.txt"), "utf8")).toContain("stub: done");
    for (const f of ["events.jsonl", "evidence.jsonl", "outcome.jsonl"]) expect(existsSync(join(c.spec.runDir, f))).toBe(true);
  });

  it("hostedKeysStrippedByDefault", async () => {
    const c = mk();
    await runOnce(c.spec);
    const { env } = recorded(c);
    for (const k of KEYS) expect(env[k], k).toBeUndefined();
    expect(env.PI_CODING_AGENT_DIR).toBe(c.spec.agentDir);

    const user = mk({ userAgentDir: true, model: { provider: "anthropic", id: "claude-x" } });
    await runOnce(user.spec);
    const kept = recorded(user).env;
    for (const k of KEYS) expect(kept[k], k).toBe("secret-" + k);
    expect(kept.PI_CODING_AGENT_DIR).toBe(user.spec.agentDir);
  });

  it("cwdIsFreshWorkspaceWithoutKeys", async () => {
    const c = mk();
    mkdirSync(join(c.spec.runDir, "workspace"), { recursive: true });
    writeFileSync(join(c.spec.runDir, "workspace/left-over.txt"), "from an earlier run");
    await runOnce(c.spec);
    const rec = recorded(c);
    expect(realpathSync(rec.cwd)).toBe(realpathSync(join(c.spec.runDir, "workspace")));
    expect(rec.listing).toEqual([]);
    // key material is not copied into the run folder, and the config is outside the workspace
    const all = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? all(join(dir, e.name)) : [join(dir, e.name)]));
    expect(all(c.spec.runDir).filter((f) => /\.key$|\.pub$|keyring|proofs/.test(f))).toEqual([]);
    expect(flagValue(rec.argv, "--paztport-config")!.startsWith(rec.cwd)).toBe(false);
    const cfg = JSON.parse(readFileSync(join(c.spec.runDir, "config.json"), "utf8"));
    expect(cfg.clientDir.startsWith(rec.cwd)).toBe(false);
  });

  it("customPayloadPassedToServer", async () => {
    const payload = join(tmp, "my-payload.md");
    writeFileSync(payload, "custom");
    for (const mode of ["on", "off", "warning"] as const) {
      const w = join(tmp, "w.md");
      writeFileSync(w, "w");
      const c = mk({ mode, payloadFile: payload, ...(mode === "warning" ? { warning: { file: w } } : {}) });
      await runOnce(c.spec);
      const cfg = JSON.parse(readFileSync(join(c.spec.runDir, "config.json"), "utf8"));
      expect(flagValue(cfg.servers[0].args, "--payload"), mode).toBe(payload);
    }
    // the clean modes send no payload at all
    const clean = mk({ mode: "clean-on", payloadFile: payload });
    await runOnce(clean.spec);
    const cfg = JSON.parse(readFileSync(join(clean.spec.runDir, "config.json"), "utf8"));
    expect(flagValue(cfg.servers[0].args, "--payload")).toBe("none");
  });

  it("a non-zero exit is an error result, not a throw", async () => {
    const c = mk({}, "fail");
    const r = await runOnce(c.spec);
    expect(r).toMatchObject({ status: "error", exitCode: 3 });
    expect(readFileSync(join(c.spec.runDir, "stderr.txt"), "utf8")).toContain("stub: failing");
    expect(JSON.parse(readFileSync(join(c.spec.runDir, "run.json"), "utf8")).status).toBe("error");
  });

  it("a pi that cannot start is an error result", async () => {
    const c = mk({ piCli: join(tmp, "no-such-cli.js") });
    const r = await runOnce(c.spec);
    expect(r.status).toBe("error");
  });

  it("timeoutKillsProcessTree", async () => {
    const c = mk({ timeoutMs: 700 }, "hang");
    const started = Date.now();
    const r = await runOnce(c.spec);
    expect(r.status).toBe("timeout");
    expect(Date.now() - started).toBeLessThan(6000);
    const gp = Number(readFileSync(c.pidfile, "utf8"));
    expect(gp).toBeGreaterThan(0);
    expect(await gone(gp)).toBe(true);
    expect(JSON.parse(readFileSync(join(c.spec.runDir, "run.json"), "utf8")).status).toBe("timeout");
  });

  it("sweeps a grandchild that outlives pi", async () => {
    const c = mk({ timeoutMs: 700 }, "hang-orphan");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("timeout");
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  });

  it("escalates to SIGKILL when SIGTERM is ignored", async () => {
    const c = mk({ timeoutMs: 500 }, "hang-ignore");
    const started = Date.now();
    const r = await runOnce(c.spec);
    expect(r.status).toBe("timeout");
    expect(Date.now() - started).toBeGreaterThanOrEqual(4500);
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  }, 20_000);

  it("detachedMcpServerStopsWithPiAfterTimeout", async () => {
    // pi-mcp starts MCP servers in their own process group, so the group kill cannot reach them; they
    // end because their stdin closes when pi dies. The stub's detached grandchild behaves the same way.
    const c = mk({ timeoutMs: 700 }, "hang-detached");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("timeout");
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  });

  it("detachedMcpServerStopsWithPiAfterSigkill", async () => {
    const c = mk({ timeoutMs: 500 }, "hang-detached-ignore");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("timeout");
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  }, 20_000);

  it("exitHookKillsLiveRunGroups", async () => {
    const c = mk({}, "hang");
    const r = spawnSync(process.execPath, [join(import.meta.dirname, "fixtures/crash-runner.ts")], { env: { ...process.env, CRASH_SPEC: JSON.stringify(c.spec) }, timeout: 20_000 });
    expect(r.status).toBe(1);
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  });

  it("multiByteCharacterSplitAcrossReadsIsNotGarbled", async () => {
    const c = mk({}, "split");
    const seen: string[] = [];
    await runOnce(c.spec, (file, line) => {
      if (file === "events") seen.push(line);
    });
    expect(seen).toEqual([JSON.stringify({ text: "caf\u00e9 \u20ac \u{1F600}" })]);
  });

  it("aFileSystemErrorOnTheTranscriptIsAnErrorResult", async () => {
    const c = mk({}, "break-transcript");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("error");
    expect(readFileSync(join(c.spec.runDir, "stderr.txt"), "utf8")).toContain("runner:");
  });

  it("repeatedFaultsLeaveNoPendingEscalationTimers", async () => {
    // pi ignores SIGTERM and the events file stays broken, so the poller faults every 100 ms. One SIGTERM and
    // one SIGKILL timer is all a run may use; nothing may keep signalling the process group once it resolves.
    const c = mk({}, "break-events-ignore");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("error");
    const kill = vi.spyOn(process, "kill");
    try {
      await new Promise((done) => setTimeout(done, 800));
      expect(kill.mock.calls.filter(([pid]) => typeof pid === "number" && pid < 0)).toEqual([]);
    } finally {
      kill.mockRestore();
    }
  }, 20_000);

  it("aFileSystemErrorOnTheEventsLogIsAnErrorResult", async () => {
    const c = mk({}, "break-events");
    const r = await runOnce(c.spec);
    expect(r.status).toBe("error");
  });

  it("abortSignalStops", async () => {
    const c = mk({}, "hang");
    const ac = new AbortController();
    const done = runOnce(c.spec, (file) => {
      if (file === "transcript") ac.abort(); // pi has started
    }, ac.signal);
    const r = await done;
    expect(r.status).toBe("error");
    expect(await gone(Number(readFileSync(c.pidfile, "utf8")))).toBe(true);
  });

  it("an already aborted signal starts nothing", async () => {
    const c = mk();
    const ac = new AbortController();
    ac.abort();
    const r = await runOnce(c.spec, undefined, ac.signal);
    expect(r.status).toBe("error");
    expect(existsSync(c.record)).toBe(false);
    expect(existsSync(join(c.spec.runDir, "run.json"))).toBe(true);
  });

  it("onLine streams transcript, stderr, events and outcome lines", async () => {
    const c = mk({}, "logs");
    const seen: [string, string][] = [];
    await runOnce(c.spec, (file, line) => seen.push([file, line]));
    const of = (f: string) => seen.filter(([k]) => k === f).map(([, l]) => l);
    expect(of("transcript").map((l) => JSON.parse(l).type)).toEqual(["session", "agent_end"]);
    expect(of("stderr")).toEqual(["stub: done"]);
    expect(of("events").map((l) => JSON.parse(l).type)).toEqual(["tool_call"]);
    expect(of("outcome").map((l) => JSON.parse(l).verdict)).toEqual(["ALLOWED"]);
  });

  it("rejects invalid specs", async () => {
    await expect(runOnce(mk({ mode: "bogus" as RunMode }).spec)).rejects.toThrow(/mode/);
    await expect(runOnce(mk({ timeoutMs: 0 }).spec)).rejects.toThrow(/timeoutMs/);
    await expect(runOnce(mk({ mode: "warning" }).spec)).rejects.toThrow(/warning/);
    await expect(runOnce(mk({ scenarioDir: join(tmp, "nope") }).spec)).rejects.toThrow(/scenario/);
  });

  it("hostedProviderNeedsAgentDir", async () => {
    const hosted = { provider: "anthropic", id: "claude-x" };
    const c = mk({ model: hosted });
    await expect(runOnce(c.spec)).rejects.toThrow(/--agent-dir/);
    expect(existsSync(c.record)).toBe(false);
    expect(() => prepareAgentDir(join(tmp, "a"), hosted)).toThrow(/--agent-dir/);
    expect(() => prepareAgentDir(join(tmp, "a"), hosted, true)).not.toThrow();
  });
});

describe("prepareAgentDir", () => {
  it("writes models.json for an ollama model and keeps earlier ones", () => {
    const dir = join(tmp, "agent-models");
    prepareAgentDir(dir, OLLAMA);
    prepareAgentDir(dir, { provider: "ollama", id: "gemma3:4b" });
    prepareAgentDir(dir, OLLAMA);
    const models = JSON.parse(readFileSync(join(dir, "models.json"), "utf8"));
    expect(models.providers.ollama).toMatchObject({ baseUrl: "http://127.0.0.1:11434/v1", api: "openai-completions", apiKey: "ollama" });
    expect(models.providers.ollama.models).toEqual([{ id: "qwen3:4b" }, { id: "gemma3:4b" }]);
  });
  it("leaves the user's own directory alone", () => {
    const dir = join(tmp, "agent-user");
    mkdirSync(dir);
    prepareAgentDir(dir, OLLAMA, true);
    expect(existsSync(join(dir, "models.json"))).toBe(false);
  });
});

describe("checkModelAvailable", () => {
  const tags = (names: string[]) => vi.fn(async () => new Response(JSON.stringify({ models: names.map((name) => ({ name, model: name })) }), { status: 200 })) as unknown as typeof fetch;

  it("missingOllamaModelIsClearError", async () => {
    const down = vi.fn(async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await expect(checkModelAvailable(OLLAMA, down)).rejects.toThrow("Ollama isn't reachable at 127.0.0.1:11434. Start it with `ollama serve`.");
    await expect(checkModelAvailable(OLLAMA, tags(["gemma3:4b"]))).rejects.toThrow("Model qwen3:4b isn't pulled. Run `ollama pull qwen3:4b`.");
    await expect(checkModelAvailable(OLLAMA, tags(["qwen3:4b"]))).resolves.toBeUndefined();
  });
  it("treats an id without a tag as :latest", async () => {
    await expect(checkModelAvailable({ provider: "ollama", id: "llama3" }, tags(["llama3:latest"]))).resolves.toBeUndefined();
  });
  it("an odd answer from the port is the same one-line message", async () => {
    const odd = vi.fn(async () => new Response("nope", { status: 500 })) as unknown as typeof fetch;
    await expect(checkModelAvailable(OLLAMA, odd)).rejects.toThrow(/Ollama isn't reachable at 127\.0\.0\.1:11434/);
    const junk = vi.fn(async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch;
    await expect(checkModelAvailable(OLLAMA, junk)).rejects.toThrow(/Ollama isn't reachable/);
  });
  it("makes no call for other providers", async () => {
    const f = vi.fn() as unknown as typeof fetch;
    await checkModelAvailable({ provider: "anthropic", id: "x" }, f);
    expect(f).not.toHaveBeenCalled();
  });
});
