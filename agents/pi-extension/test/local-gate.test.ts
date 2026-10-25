// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBashToolDefinition,
  createEditToolDefinition,
  createFindToolDefinition,
  createGrepToolDefinition,
  createLsToolDefinition,
  createReadToolDefinition,
  createWriteToolDefinition,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  bindLocalTool,
  commitInfluence,
  decode,
  NonceCache,
  NONCE_TTL_MS,
  rulesHash,
  verifyChainV2,
  type InfluenceEntry,
  type StampV2,
} from "@paztport/path-attest";
import type { ExtensionMode } from "../src/config.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceLog } from "../src/evidence.ts";
import { InfluenceStore } from "../src/influence.ts";
import { loadClientMaterial, type ClientMaterial } from "../src/keys.ts";
import { BUILTIN_LOCAL_TOOLS, LocalGate } from "../src/local/gate.ts";
import { localRefusalText, refusalText, SCOPE_TEXT, UNCHECKABLE_TEXT } from "../src/refusals.ts";
import { RunState } from "../src/runs.ts";
import { setupDemo, UNSAFE_TEXT } from "./helpers/demo.ts";

let tmp: string;
let material: ClientMaterial;
let ws: string;
let secret: string;
beforeAll(() => {
  tmp = realpathSync.native(mkdtempSync(join(tmpdir(), "paztport-gate-")));
  const demo = setupDemo(tmp);
  material = loadClientMaterial(join(demo, "client"), join(demo, "client/local-tools"));
  ws = join(tmp, "ws");
  for (const d of ["website", "notes", "secret"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "website", "README.md"), "# Acme\n");
  writeFileSync(join(ws, "notes", "a.md"), "note\n");
  secret = join(ws, "secret");
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let n = 0;
type Rig = { gate: LocalGate; influence: InfluenceStore; runs: RunState; eventsPath: string; evidencePath: string };

function rig(mode: ExtensionMode, opts: { material?: ClientMaterial; run?: boolean; events?: EventLog } = {}): Rig {
  const eventsPath = join(tmp, `events-${n}.jsonl`);
  const evidencePath = join(tmp, `evidence-${n++}.jsonl`);
  const influence = new InfluenceStore();
  const runs = new RunState();
  if (opts.run !== false) runs.start("Fix the README typo.", 1_000);
  const gate = new LocalGate({
    mode,
    material: opts.material ?? material,
    influence,
    runs,
    events: opts.events ?? new EventLog(eventsPath),
    evidence: new EvidenceLog(evidencePath),
    now: () => 2_000,
    workspace: ws,
    refused: [secret],
  });
  return { gate, influence, runs, eventsPath, evidencePath };
}

const lines = (path: string): Record<string, any>[] =>
  readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** The demo material with one extra route listed; the proof is a copy, enough for the gate's presence check. */
function withRoute(tool: string): ClientMaterial {
  return { ...material, proofs: { ...material.proofs, [`session/pi/local:${tool}`]: material.proofs["session/pi/local:read"]! } };
}

const taint = (influence: InfluenceStore) => influence.recordClasses("github", ["third-party", "private"], "h1");

describe("refusal texts", () => {
  it("localTextsAreExact", () => {
    expect(SCOPE_TEXT).toBe("Paztport refused this action: it is outside what this session is allowed to do, so it was not carried out.");
    expect(UNCHECKABLE_TEXT).toBe("Paztport couldn't check this command, so it wasn't run. Use simple commands with plain paths.");
    expect(localRefusalText("INFLUENCE_DENIED")).toBe(UNSAFE_TEXT);
    expect(localRefusalText("SCOPE_DENIED")).toBe(SCOPE_TEXT);
    expect(localRefusalText("PATH_NOT_ALLOWED")).toBe(SCOPE_TEXT);
    expect(localRefusalText("UNCHECKABLE")).toBe(UNCHECKABLE_TEXT);
  });

  it("mcpTextUnchanged", () => {
    expect(refusalText("INFLUENCE_DENIED")).toBe(UNSAFE_TEXT);
    expect(refusalText("UNSAFE_SESSION")).toBe(UNSAFE_TEXT);
    expect(refusalText("REPLAY")).toBe("Paztport refused this call: REPLAY");
  });

  it("builtinList", () => {
    expect([...BUILTIN_LOCAL_TOOLS]).toEqual(["read", "write", "edit", "bash", "grep", "find", "ls", "powershell"]);
  });
});

describe("LocalGate verdicts", () => {
  it("allowsAReadInScope", () => {
    const { gate, eventsPath } = rig("enforce");
    expect(gate.check("read", { path: "website/README.md" }, "c1")).toEqual({ block: false });
    expect(lines(eventsPath)).toMatchObject([{ type: "local", tool: "read", callId: "c1", verdict: "OK" }]);
  });

  it("unknownRouteIsScopeText", () => {
    const { gate, eventsPath } = rig("enforce");
    expect(gate.check("other_tool", { x: 1 }, "c1")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.check("powershell", { command: "dir" }, "c2")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(["PATH_NOT_ALLOWED", "PATH_NOT_ALLOWED"]);
  });

  it("uncheckableBash", () => {
    const { gate, eventsPath } = rig("enforce");
    expect(gate.check("bash", { command: "cat $HOME/x" }, "c1")).toEqual({ block: true, reason: UNCHECKABLE_TEXT });
    expect(gate.check("bash", { command: 42 }, "c2")).toEqual({ block: true, reason: UNCHECKABLE_TEXT });
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(["UNCHECKABLE", "UNCHECKABLE"]);
  });

  it("powershellIsAlwaysUncheckableWhenListed", () => {
    const { gate } = rig("enforce", { material: withRoute("powershell") });
    expect(gate.check("powershell", { command: "Get-ChildItem" }, "c1")).toEqual({ block: true, reason: UNCHECKABLE_TEXT });
  });

  it("scopeDenied", () => {
    const { gate, eventsPath } = rig("enforce");
    // the root folder is read-only, the refused folder is never reachable, outside is outside
    expect(gate.check("write", { path: "top.md", content: "x" }, "c1")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.check("read", { path: "secret/k" }, "c2")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.check("read", { path: "/etc/hosts" }, "c3")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.check("bash", { command: "curl x" }, "c4")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.check("ls", {}, "c5")).toEqual({ block: true, reason: SCOPE_TEXT }); // walks into secret/
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(Array(5).fill("SCOPE_DENIED"));
  });

  it("influenceDenied", () => {
    const { gate, influence, eventsPath } = rig("enforce");
    expect(gate.check("write", { path: "website/README.md", content: "x" }, "c1")).toEqual({ block: false });
    taint(influence);
    expect(gate.check("write", { path: "website/README.md", content: "x" }, "c2")).toEqual({ block: true, reason: UNSAFE_TEXT });
    expect(gate.check("edit", { path: "website/README.md", edits: [] }, "c3")).toEqual({ block: true, reason: UNSAFE_TEXT });
    // a private destination and reads stay open
    expect(gate.check("write", { path: "notes/x.md", content: "x" }, "c4")).toEqual({ block: false });
    expect(gate.check("bash", { command: "cat website/README.md" }, "c5")).toEqual({ block: false });
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(["OK", "INFLUENCE_DENIED", "INFLUENCE_DENIED", "OK", "OK"]);
  });

  it("listedOtherToolHasOnlyItsRoute", () => {
    const { gate, influence } = rig("enforce", { material: withRoute("other_tool") });
    taint(influence);
    expect(gate.check("other_tool", { path: "/etc/hosts" }, "c1")).toEqual({ block: false });
    expect(gate.labelsFor("c1")).toEqual(["local-untrusted"]);
  });
});

describe("LocalGate modes", () => {
  it("offNeverBlocksAndWritesNothing", () => {
    const { gate, influence, eventsPath, evidencePath } = rig("off");
    taint(influence);
    for (const [tool, input] of [
      ["write", { path: "website/README.md", content: "x" }],
      ["bash", { command: "curl x" }],
      ["other_tool", {}],
      ["powershell", { command: "dir" }],
    ] as const) {
      expect(gate.check(tool, input, `c-${tool}`)).toEqual({ block: false });
      expect(gate.labelsFor(`c-${tool}`)).toBeUndefined();
    }
    expect(readFileSync(eventsPath, "utf8")).toBe("");
    expect(readFileSync(evidencePath, "utf8")).toBe("");
  });

  it("noRootRefusesEverything", () => {
    const { gate, eventsPath, evidencePath } = rig("no-root");
    for (const tool of ["read", "ls", "write", "bash", "other_tool"]) {
      expect(gate.check(tool, { path: "website/README.md", command: "ls" }, `c-${tool}`)).toEqual({ block: true, reason: SCOPE_TEXT });
      expect(gate.labelsFor(`c-${tool}`)).toBeUndefined();
    }
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(Array(5).fill("SCOPE_DENIED"));
    expect(readFileSync(evidencePath, "utf8")).toBe("");
  });

  it("enforceWithoutRulesRefusesEverything", () => {
    const { rules: _rules, ...bare } = material;
    const { gate, eventsPath, evidencePath } = rig("enforce", { material: bare });
    expect(gate.check("read", { path: "website/README.md" }, "c1")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(lines(eventsPath).map((e) => e.verdict)).toEqual(["SCOPE_DENIED"]);
    const [rec] = lines(evidencePath);
    expect(rec).toMatchObject({ type: "local", tool: "read", callId: "c1", verdict: "SCOPE_DENIED", routeAllowed: true, rulesHash: null });
    // with no rules nothing is resolved, and the stamp binds that and the verdict
    expect(rec!.resolved).toEqual({ paths: [], programs: [], parse: "ok", readOnly: false });
    expect(rec!.chain[1].bind).toBe(bindLocalTool("read", rec!.input, { resolved: rec!.resolved, verdict: "SCOPE_DENIED", routeAllowed: true, rulesHash: null }));
  });

  it("noActiveRunRefusesWithAnEventOnly", () => {
    const { gate, eventsPath, evidencePath } = rig("enforce", { run: false });
    expect(gate.check("read", { path: "website/README.md" }, "c1")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(lines(eventsPath)).toEqual([{ ts: expect.any(Number), type: "local", tool: "read", callId: "c1", verdict: "SCOPE_DENIED" }]);
    expect(readFileSync(evidencePath, "utf8")).toBe("");
  });
});

describe("LocalGate labels", () => {
  let r: Rig;
  beforeEach(() => {
    r = rig("enforce");
  });

  it("readToolsGiveFolderLabels", () => {
    expect(r.gate.check("read", { path: "website/README.md" }, "c1").block).toBe(false);
    expect(r.gate.labelsFor("c1")).toEqual(["public"]);
    expect(r.gate.labelsFor("c1")).toBeUndefined(); // forgotten once taken
    expect(r.gate.check("read", { path: "notes/a.md" }, "c2").block).toBe(false);
    expect(r.gate.labelsFor("c2")).toEqual(["local-untrusted"]);
    expect(r.gate.check("grep", { pattern: "x", path: "website" }, "c3").block).toBe(false);
    expect(r.gate.labelsFor("c3")).toEqual(["public"]);
  });

  it("bashAddsLocalUntrusted", () => {
    expect(r.gate.check("bash", { command: "cat website/README.md" }, "c1").block).toBe(false);
    expect([...r.gate.labelsFor("c1")!].sort()).toEqual(["local-untrusted", "public"]);
  });

  it("writesGiveNoLabelsAndRefusalsNone", () => {
    expect(r.gate.check("write", { path: "notes/x.md", content: "x" }, "c1").block).toBe(false);
    expect(r.gate.labelsFor("c1")).toEqual([]);
    expect(r.gate.check("read", { path: "/etc/hosts" }, "c2").block).toBe(true);
    expect(r.gate.labelsFor("c2")).toBeUndefined();
  });
});

describe("LocalGate evidence", () => {
  it("signsEveryCheckedCall", () => {
    const { gate, influence, evidencePath, runs } = rig("enforce");
    gate.check("read", { path: "website/README.md" }, "c1");
    taint(influence);
    gate.check("write", { path: "website/README.md", content: "leak" }, "c2");
    gate.check("other_tool", {}, "c3");
    const recs = lines(evidencePath);
    expect(recs.map((x) => [x.tool, x.callId, x.verdict])).toEqual([
      ["read", "c1", "OK"],
      ["write", "c2", "INFLUENCE_DENIED"],
      ["other_tool", "c3", "PATH_NOT_ALLOWED"],
    ]);
    const rid = runs.current()!.rid;
    for (const rec of recs) {
      expect(rec).toMatchObject({ v: 1, type: "local", rid, now: 2_000 });
      const [origin, pi] = rec.chain as [StampV2, StampV2];
      expect(origin.sess).toBe("");
      expect(pi.sess).toBe("");
      expect(pi.prev).toBe(origin.sig);
      // the binding covers the decision too: what was resolved, the verdict, whether the route is listed, and which rules
      expect(rec.routeAllowed).toBe(rec.proof !== null);
      expect(rec.rulesHash).toBe(rulesHash(material.rules!));
      expect(pi.bind).toBe(bindLocalTool(rec.tool, rec.input, { resolved: rec.resolved, verdict: rec.verdict, routeAllowed: rec.routeAllowed, rulesHash: rec.rulesHash }));
      expect(pi.infl).toBe(commitInfluence(rec.influence as InfluenceEntry[]));
      expect(pi.ts).toBe(2_000);
      expect([origin.svc, pi.svc, pi.inst]).toEqual(["session", "pi", "pi-1"]);
      const route = `session/pi/local:${rec.tool}`;
      expect(rec.proof).toEqual(Object.hasOwn(material.proofs, route) ? material.proofs[route] : null);
    }
    expect(recs[0]!.influence).toEqual([]);
    expect(recs[1]!.influence).toEqual(influence.entries());
    expect(recs[0]!.resolved).toEqual({ paths: [{ need: "read", at: "website/README.md" }], programs: [], parse: "ok", readOnly: true });
    expect(recs[0]!.input).toEqual({ path: "website/README.md" });

    // the full v2 chain check, with the route as receiver
    for (const rec of recs.slice(0, 2)) {
      const v = verifyChainV2(
        { stamps: rec.chain, expectedBind: bindLocalTool(rec.tool, rec.input, { resolved: rec.resolved, verdict: rec.verdict, routeAllowed: rec.routeAllowed, rulesHash: rec.rulesHash }), influence: rec.influence, proof: rec.proof, receiver: `local:${rec.tool}` },
        {
          keyring: material.keyring,
          root: decode(material.signedRoot.root),
          rootId: material.signedRoot.rootId,
          allowedOrigins: ["session"],
          sess: "",
          nonces: new NonceCache(NONCE_TTL_MS),
          nonceKey: rec.callId,
          now: rec.now,
        },
      );
      expect(v).toMatchObject({ ok: true, reason: "OK" });
    }
    // one origin per run: every record chains from the same origin stamp
    expect(new Set(recs.map((x) => x.chain[0].sig)).size).toBe(1);
  });

  it("eventsNeverCarryPathsOrContent", () => {
    const { gate, influence, eventsPath } = rig("enforce");
    gate.check("read", { path: "website/README.md" }, "c1");
    gate.check("bash", { command: "cat website/README.md notes/a.md" }, "c2");
    taint(influence);
    gate.check("write", { path: "website/README.md", content: "SECRET-CONTENT" }, "c3");
    gate.check("read", { path: "/etc/hosts" }, "c4");
    gate.check("bash", { command: "cat $(ls website/)" }, "c5");
    const evs = lines(eventsPath);
    expect(evs).toHaveLength(5);
    for (const e of evs) {
      const s = JSON.stringify(e);
      expect(s).not.toContain("website/");
      expect(s).not.toContain("notes/");
      expect(s).not.toContain("/etc");
      expect(s).not.toContain("SECRET-CONTENT");
      expect(Object.keys(e).sort()).toEqual(["callId", "rid", "tool", "ts", "type", "verdict"]);
    }
  });
});

describe("LocalGate input", () => {
  it("freezesAllowedInputOnly", () => {
    const { gate, influence } = rig("enforce");
    const allowed = { path: "website/README.md", content: "x", nested: { list: ["a"] } };
    expect(gate.check("write", allowed, "c1").block).toBe(false);
    expect(Object.isFrozen(allowed) && Object.isFrozen(allowed.nested) && Object.isFrozen(allowed.nested.list)).toBe(true);
    expect(() => {
      (allowed as Record<string, unknown>).path = "notes/x.md";
    }).toThrow(TypeError);
    taint(influence);
    const refused = { path: "website/README.md", content: "x" };
    expect(gate.check("write", refused, "c2").block).toBe(true);
    expect(Object.isFrozen(refused)).toBe(false);
    const off = { path: "website/README.md" };
    expect(rig("off").gate.check("read", off, "c3").block).toBe(false);
    expect(Object.isFrozen(off)).toBe(false);
  });

  it("anyThrowRefusesWithScopeText", () => {
    const events = { emit: () => { throw new Error("raw internal detail"); } } as unknown as EventLog;
    const { gate } = rig("enforce", { events });
    expect(gate.check("read", { path: "website/README.md" }, "c1")).toEqual({ block: true, reason: SCOPE_TEXT });
    expect(gate.labelsFor("c1")).toBeUndefined();
  });
});

describe("pi's built-in tools with frozen input", () => {
  // The gate deep-freezes an allowed call's input, and pi hands that object to execute. pi's built-ins
  // only destructure and read their params (edit's prepareArguments, which does mutate, runs on the raw
  // arguments before pi's validation clones them, so it never sees this object). Each tool is run here
  // on frozen input: a write to it would throw a TypeError. PI_OFFLINE keeps grep and find from
  // downloading rg or fd.
  let dir: string;
  beforeEach(() => {
    vi.stubEnv("PI_OFFLINE", "1");
    dir = mkdtempSync(join(tmp, "frozen-"));
    writeFileSync(join(dir, "a.md"), "hello world\n");
  });
  afterEach(() => vi.unstubAllEnvs());

  const frozen = <T>(v: T): T => {
    const walk = (x: unknown) => {
      if (typeof x === "object" && x !== null) {
        Object.freeze(x);
        Object.values(x).forEach(walk);
      }
    };
    walk(v);
    return v;
  };
  const MUTATION = /read[- ]only|not extensible|Cannot (assign|delete|add|define)/i;
  const cases: [string, (cwd: string) => ToolDefinition<any, any>, Record<string, unknown>][] = [
    ["read", (c) => createReadToolDefinition(c), { path: "a.md", offset: 1, limit: 5 }],
    ["write", (c) => createWriteToolDefinition(c), { path: "b.md", content: "new\n" }],
    ["edit", (c) => createEditToolDefinition(c), { path: "a.md", edits: [{ oldText: "hello", newText: "hi" }] }],
    ["bash", (c) => createBashToolDefinition(c), { command: "cat a.md", timeout: 10 }],
    ["grep", (c) => createGrepToolDefinition(c), { pattern: "world", path: ".", glob: "*.md", ignoreCase: true, limit: 5 }],
    ["find", (c) => createFindToolDefinition(c), { pattern: "*.md", path: ".", limit: 5 }],
    ["ls", (c) => createLsToolDefinition(c), { path: ".", limit: 5 }],
  ];
  for (const [name, make, input] of cases) {
    it(`${name}DoesNotMutateItsInput`, async () => {
      const params = frozen(structuredClone(input));
      try {
        const out = await make(dir).execute("t1", params, undefined, undefined, undefined as never);
        expect(out.content.length).toBeGreaterThan(0);
      } catch (e) {
        // only a missing rg or fd (offline) may fail, never a write to the frozen input
        expect(String((e as Error).message)).not.toMatch(MUTATION);
        expect(["grep", "find"]).toContain(name);
      }
      expect(params).toEqual(input);
    });
  }
});
