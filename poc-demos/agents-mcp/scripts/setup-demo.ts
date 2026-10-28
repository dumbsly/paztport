// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Generates demo keys and signed policies: <out>/server (mcp-entry, github-tools) and <out>/client (session, pi),
// plus <out>/client/local-tools (the client root with the local folder rules), <out>/client/server-policy.pub, the server policy public key the client pins,
// and <out>/server/client-policy.pub, the client policy public key the server pins, and <out>/server/reply-cert.json,
// a 30-day reply certificate for mcp-entry's key, the key that signs the server's session replies. Neither policy
// private key is kept: each is deleted once it has signed its side's root and keyring, and the server's its certificate.
// Refuses an existing <out> unless --force (which regenerates the keys in place).
// Prints only paths, never key material.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const AGENTS = join(import.meta.dirname, "..");
const KEYGEN = join(AGENTS, "node_modules/@paztport/policy-tool/src/keygen.ts");
const POLICY = join(AGENTS, "node_modules/@paztport/policy-tool/src/policy.ts");

function run(script: string, args: string[]): void {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  if (r.status !== 0) {
    console.error(r.stderr || r.stdout);
    process.exit(r.status ?? 1);
  }
}

/** Keys, keyring, root and proofs into `dir`; `extra` is passed to the policy tool. */
function setup(dir: string, services: string, paths: string, extra: string[] = []): void {
  run(KEYGEN, ["--out", dir, "--services", services]);
  run(POLICY, ["--paths", paths, "--policy-key", join(dir, "policy.key"), "--out", dir, ...extra]);
  console.log(dir);
}

const USAGE = "Usage: node setup-demo.ts [--out poc-demos/agents-mcp/.demo] [--force]";

let out: string;
let force: boolean;
try {
  const { values } = parseArgs({ options: { out: { type: "string" }, force: { type: "boolean" } }, strict: true });
  out = resolve(values.out ?? join(AGENTS, ".demo"));
  force = values.force ?? false;
} catch (e) {
  console.error((e as Error).message);
  console.error(USAGE);
  process.exit(2);
}
if (existsSync(out) && !force) {
  console.error(`${out} already exists; pass --force to regenerate its keys`);
  console.error(USAGE);
  process.exit(2);
}
// keygen signs the server keyring; the policy tool signs the root and the certificate for mcp-entry's key
setup(join(out, "server"), "mcp-entry,github-tools", join(AGENTS, "policies/server.paths.yaml"), [
  "--reply-cert-svc", "mcp-entry",
  "--keyring", join(out, "server/keyring.json"),
  "--reply-cert-days", "30",
]);
// the server's session replies are signed by mcp-entry's key, so its policy key has nothing left to sign
rmSync(join(out, "server/policy.key"));
setup(join(out, "client"), "session,pi", join(AGENTS, "policies/client.paths.yaml"));
// the same client policy key also signs a second root that binds the local folder rules (read by the pi extension)
run(POLICY, [
  "--paths", join(AGENTS, "policies/client-local-tools.paths.yaml"),
  "--policy-key", join(out, "client/policy.key"),
  "--out", join(out, "client/local-tools"),
]);
// the server opens attested sessions only for the client policy key it pins
const clientRing = JSON.parse(readFileSync(join(out, "client/keyring.json"), "utf8")) as { policy: string };
const clientPin = join(out, "server/client-policy.pub");
writeFileSync(clientPin, clientRing.policy + "\n");
console.log(clientPin);
rmSync(join(out, "client/policy.key"));
const serverRing = JSON.parse(readFileSync(join(out, "server/keyring.json"), "utf8")) as { policy: string };
const pin = join(out, "client/server-policy.pub");
writeFileSync(pin, serverRing.policy + "\n");
console.log(pin);
