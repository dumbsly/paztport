// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A fake pi CLI for runner tests. It records argv, env, cwd and the cwd listing to $STUB_RECORD, then
// behaves as $STUB_BEHAVIOR says:
//   print       two JSON lines on stdout, one line on stderr, exit 0 (default)
//   fail        one line on stderr, exit 3
//   hang        spawns a sleeping grandchild (pid in $STUB_PIDFILE), then waits forever
//   hang-ignore does the same, and both the stub and the grandchild ignore SIGTERM
//   hang-orphan the stub dies on SIGTERM but its grandchild ignores it
//   hang-detached         a grandchild in its own process group (as pi-mcp starts MCP servers) that exits when its stdin closes
//   hang-detached-ignore  the same, and the stub ignores SIGTERM
//   split       appends one events line in two writes, cut inside a multi-byte character, then prints
//   break-transcript / break-events  replace that run file with a directory, then print
//   break-events-ignore   as break-events, but ignores SIGTERM and then hangs
//   logs        appends a line to the extension's events log and the server's outcome log, then prints
//   provider-error  what pi 1.4.0 --mode json does when the model provider fails: a tool call (with its
//               outcome record, as the mock server writes it), then a final assistant message with
//               stopReason "error" and an errorMessage, agent_end, and exit 0
//   provider-error-early  the same with no tool call and no outcome record
//   answer      a final assistant message with stopReason "stop", agent_end, exit 0
//   paths       prints the session header with its cwd, then a line holding the run dir, the workspace,
//               the agents dir and the home dir, then a final answer; exit 0

import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

// A local-tools run starts pi with an allowlisted environment, which has no STUB_* variables. The test then
// leaves them in stub-env.json beside config.json; they are applied after the real environment is captured.
const realEnv = { ...process.env };
{
  const i = process.argv.indexOf("--paztport-config");
  const file = i < 0 ? "" : join(dirname(process.argv[i + 1] ?? ""), "stub-env.json");
  try {
    Object.assign(process.env, JSON.parse(readFileSync(file, "utf8")));
  } catch {
    // no such file: the variables came in the environment
  }
}
const behavior = process.env.STUB_BEHAVIOR ?? "print";
const record = process.env.STUB_RECORD;
if (record) {
  writeFileSync(record, JSON.stringify({ argv: process.argv.slice(2), env: realEnv, cwd: process.cwd(), listing: readdirSync(process.cwd()) }));
}

function flag(name: string): string {
  const i = process.argv.indexOf(name);
  return i < 0 ? "" : (process.argv[i + 1] ?? "");
}

if (behavior === "break-events-ignore") {
  process.on("SIGTERM", () => {});
  const file = join(dirname(flag("--paztport-config")), "events.jsonl");
  rmSync(file);
  mkdirSync(file);
  console.log(JSON.stringify({ type: "session" }));
  setInterval(() => {}, 1000);
} else if (behavior === "fail") {
  console.error("stub: failing");
  process.exit(3);
} else if (behavior.startsWith("hang")) {
  if (behavior === "hang-ignore" || behavior === "hang-detached-ignore") process.on("SIGTERM", () => {});
  const detached = behavior.startsWith("hang-detached");
  const grandchildIgnores = behavior === "hang-ignore" || behavior === "hang-orphan";
  const code = detached
    ? "process.stdin.on('end',()=>process.exit(0));process.stdin.resume()"
    : (grandchildIgnores ? "process.on('SIGTERM',()=>{});" : "") + "setInterval(()=>{},1000)";
  const child = spawn(process.execPath, ["-e", code, "paztport-stub-grandchild", process.env.STUB_MARK ?? ""], {
    stdio: [detached ? "pipe" : "ignore", "ignore", "ignore"],
    detached,
  });
  writeFileSync(process.env.STUB_PIDFILE!, String(child.pid));
  console.log(JSON.stringify({ type: "session" }));
  setInterval(() => {}, 1000);
} else {
  if (behavior === "break-transcript" || behavior === "break-events") {
    const file = join(dirname(flag("--paztport-config")), behavior === "break-events" ? "events.jsonl" : "transcript.jsonl");
    rmSync(file);
    mkdirSync(file);
    if (behavior === "break-events") await new Promise((r) => setTimeout(r, 400));
  }
  if (behavior === "split") {
    const cfg = JSON.parse(readFileSync(flag("--paztport-config"), "utf8"));
    const bytes = Buffer.from(JSON.stringify({ text: "caf\u00e9 \u20ac \u{1F600}" }) + "\n");
    const cut = bytes.indexOf(Buffer.from("\u20ac")) + 1; // inside the 3-byte euro sign
    appendFileSync(cfg.eventsLog, bytes.subarray(0, cut));
    await new Promise((r) => setTimeout(r, 400));
    appendFileSync(cfg.eventsLog, bytes.subarray(cut));
  }
  if (behavior === "logs") {
    const cfg = JSON.parse(readFileSync(flag("--paztport-config"), "utf8"));
    appendFileSync(cfg.eventsLog, JSON.stringify({ type: "tool_call", tool: "x" }) + "\n");
    const args: string[] = cfg.servers[0].args;
    appendFileSync(args[args.indexOf("--outcome-log") + 1]!, JSON.stringify({ verdict: "ALLOWED" }) + "\n");
  }
  const assistant = (stopReason: string, errorMessage?: string) => ({ role: "assistant", content: [], stopReason, ...(errorMessage ? { errorMessage } : {}) });
  if (behavior === "provider-error" || behavior === "provider-error-early") {
    console.log(JSON.stringify({ type: "session", cwd: process.cwd() }));
    if (behavior === "provider-error") {
      const cfg = JSON.parse(readFileSync(flag("--paztport-config"), "utf8"));
      const args: string[] = cfg.servers[0].args;
      const mode = args[args.indexOf("--mode") + 1];
      const record = { ts: Date.now(), mode, tool: "list_issues", kind: "read", owner: "acme", repo: "website", publicDestination: false, privateRead: false, privateFileRead: false, isError: false, containsCanary: false, containsPrivateMarker: false, verdict: "ALLOWED", audit: false };
      appendFileSync(args[args.indexOf("--outcome-log") + 1]!, JSON.stringify(record) + "\n");
      console.log(JSON.stringify({ type: "tool_execution_start", toolCallId: "c1", toolName: "mcp__github__list_issues", args: {} }));
    }
    console.log(JSON.stringify({ type: "message_end", message: assistant("error", "500 model failed to load") }));
    console.log(JSON.stringify({ type: "agent_end", messages: [assistant("error", "500 model failed to load")] }));
    console.error("stub: done");
    process.exit(0);
  }
  if (behavior === "paths") {
    const runDir = dirname(flag("--paztport-config"));
    const agents = resolve(import.meta.dirname, "../../..");
    console.log(JSON.stringify({ type: "session", cwd: process.cwd() }));
    console.log(JSON.stringify({ type: "note", runDir, workspace: join(runDir, "workspace"), agents: join(agents, "eval/src/x.ts"), home: join(homedir(), ".pi/agent") }));
    console.error(`stub: read ${join(homedir(), ".pi/agent/settings.json")} from ${process.cwd()}`);
  } else {
    console.log(JSON.stringify({ type: "session" }));
  }
  if (behavior === "answer" || behavior === "paths") {
    console.log(JSON.stringify({ type: "message_end", message: assistant("stop") }));
    console.log(JSON.stringify({ type: "agent_end", messages: [assistant("stop")] }));
  } else {
    console.log(JSON.stringify({ type: "agent_end" }));
  }
  console.error("stub: done");
}
