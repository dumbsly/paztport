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
//   logs        appends a line to the extension's events log and the server's outcome log, then prints

import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const behavior = process.env.STUB_BEHAVIOR ?? "print";
const record = process.env.STUB_RECORD;
if (record) {
  writeFileSync(record, JSON.stringify({ argv: process.argv.slice(2), env: process.env, cwd: process.cwd(), listing: readdirSync(process.cwd()) }));
}

function flag(name: string): string {
  const i = process.argv.indexOf(name);
  return i < 0 ? "" : (process.argv[i + 1] ?? "");
}

if (behavior === "fail") {
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
  console.log(JSON.stringify({ type: "session" }));
  console.log(JSON.stringify({ type: "agent_end" }));
  console.error("stub: done");
}
