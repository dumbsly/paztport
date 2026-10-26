// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The local gate: every tool call that is not one of this extension's MCP tools is checked here, in
// pi's tool_call hook, against the signed client rules before it runs.

import { homedir } from "node:os";
import { bindLocalTool, commitInfluence, influenceClasses, rulesHash, signStampV2, type InfluenceClass, type LocalRules } from "@paztport/path-attest";
import type { ExtensionMode } from "../config.ts";
import type { EventLog } from "../events.ts";
import type { EvidenceLog } from "../evidence.ts";
import type { InfluenceStore } from "../influence.ts";
import type { ClientMaterial } from "../keys.ts";
import { localRefusalText, SCOPE_TEXT } from "../refusals.ts";
import type { RunState } from "../runs.ts";
import { PINNED_PATH, resolveBash } from "./bash.ts";
import { decideLocal, readLabels, type LocalVerdict, type Resolved } from "./decide.ts";
import { canonical, resolveFileTool, type PathContext } from "./paths.ts";
import { encodePlaceholders } from "./placeholders.ts";

/** pi's built-in local tools. */
export const BUILTIN_LOCAL_TOOLS = ["read", "write", "edit", "bash", "grep", "find", "ls", "powershell"] as const;

type FileTool = Exclude<(typeof BUILTIN_LOCAL_TOOLS)[number], "bash" | "powershell">;
const FILE_TOOLS: readonly string[] = BUILTIN_LOCAL_TOOLS.filter((t): t is FileTool => t !== "bash" && t !== "powershell");
const READ_TOOLS: readonly string[] = FILE_TOOLS.filter((t) => t !== "write" && t !== "edit");
const ROUTE_PREFIX = "session/pi/local:";
const INST = "pi-1";

/** Nothing resolved: a tool with no paths of its own, or a call refused before resolution. */
const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };
const UNPARSED: Resolved = { paths: [], programs: [], parse: "error", readOnly: false };

export type LocalGateDeps = {
  mode: ExtensionMode;
  material: ClientMaterial;
  influence: InfluenceStore;
  runs: RunState;
  events: EventLog;
  evidence: EvidenceLog;
  now: () => number;
  /** pi's cwd for the session: where relative paths resolve and what workspace-relative paths are recorded against. */
  workspace: string;
  /** Absolute paths no call may touch (keys, config, logs, pi's own folders). */
  refused: readonly string[];
  /** The home folder named "<home>" in signed input (default: the user's home folder). */
  home?: string;
};

/** Freezes a JSON-like value and everything in it, so an in-place change throws in strict code. */
function deepFreeze(v: unknown): void {
  if (typeof v === "object" && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const x of Object.values(v)) {
      deepFreeze(x);
    }
  }
}

/** A path and, when it resolves, its real path; a path that can't be resolved is named as given. */
function spellings(path: string): string[] {
  try {
    return [path, canonical(path)];
  } catch {
    return [path];
  }
}

/**
 * Checks pi tool calls against the signed client rules. In enforce mode each checked call during a
 * run is a signed client-mesh step: a v2 stamp with an empty `sess`, chained from the run's origin and
 * bound to the input and the decision (the call id, what the gate resolved, the verdict, whether the route
 * is listed and the rules' hash), written to the evidence file with the route proof and the influence. The
 * input is bound and recorded with the workspace and home folder paths replaced by "<workspace>" and "<home>"
 * (encodePlaceholders, reversible); the tool runs with the input as given. no-root mode has no rules to check against and refuses every call.
 * off mode allows everything and records nothing.
 *
 * pi's tool_call input is mutable, later handlers see the same object, and the tool runs with it
 * unvalidated. So an allowed call's input is deep-frozen once checked: a later handler that changes it
 * in place throws, and pi turns the throw into a blocked call. pi's built-in tools only read their params.
 */
export class LocalGate {
  private readonly deps: LocalGateDeps;
  /** Read labels of allowed calls, until tool_result takes them. */
  private readonly labels = new Map<string, InfluenceClass[]>();

  constructor(deps: LocalGateDeps) {
    this.deps = deps;
  }

  /**
   * Synchronous, so the verdict and its stamp commit to the influence and run current when the call was
   * made. Never throws: anything unexpected refuses the call with the scope text.
   */
  check(toolName: string, input: Record<string, unknown>, toolCallId: string): { block: boolean; reason?: string } {
    try {
      return this.decide(toolName, input, toolCallId);
    } catch {
      this.labels.delete(toolCallId);
      return { block: true, reason: SCOPE_TEXT };
    }
  }

  private decide(toolName: string, input: Record<string, unknown>, toolCallId: string): { block: boolean; reason?: string } {
    const { mode, material, influence, runs, events, evidence } = this.deps;
    if (mode === "off") {
      return { block: false };
    }
    const run = runs.current();
    const emit = (verdict: LocalVerdict) =>
      events.emit({ type: "local", tool: toolName, callId: toolCallId, ...(run !== undefined ? { rid: run.rid } : {}), verdict });
    if (mode === "no-root" || run === undefined) {
      // no rules to check against, or no user prompt to chain from: nothing is signed
      emit("SCOPE_DENIED");
      return { block: true, reason: localRefusalText("SCOPE_DENIED") };
    }

    const route = ROUTE_PREFIX + toolName;
    const proof = Object.hasOwn(material.proofs, route) ? material.proofs[route]! : null;
    const entries = influence.entries();
    const rules = material.rules;
    let resolved = NOTHING;
    let verdict: LocalVerdict = "SCOPE_DENIED";
    if (rules !== undefined) {
      if (proof !== null) {
        resolved = this.resolve(toolName, input, rules);
      }
      verdict = decideLocal({ routeAllowed: proof !== null, resolved, rules, classes: influenceClasses(entries) });
    }

    try {
      const origin = runs.origin("", material.sessionKey, INST);
      const now = this.deps.now();
      const routeAllowed = proof !== null;
      const hash = rules !== undefined ? rulesHash(rules) : null;
      const signedInput = encodePlaceholders(input, { workspace: spellings(this.deps.workspace), home: spellings(this.deps.home ?? homedir()) });
      // the stamp binds the decision as well as the call: the call id, what was resolved, the verdict, whether
      // the route is listed and which rules decided, so none of them can be changed in the evidence after signing
      const bind = bindLocalTool(toolName, signedInput, { callId: toolCallId, resolved, verdict, routeAllowed, rulesHash: hash });
      const stamp = signStampV2({ svc: "pi", inst: INST, rid: run.rid, ts: now, sess: "", bind, infl: commitInfluence(entries), prev: origin.sig }, material.piKey);
      evidence.write({
        v: 1,
        type: "local",
        tool: toolName,
        callId: toolCallId,
        rid: run.rid,
        now,
        input: signedInput,
        resolved,
        routeAllowed,
        rulesHash: hash,
        chain: [origin, stamp],
        proof,
        influence: entries,
        verdict,
      });
    } catch {
      // input JCS rejects (a lone surrogate, a non-finite number) cannot be bound: refuse it unsigned
      verdict = "UNCHECKABLE";
    }
    emit(verdict);
    if (verdict !== "OK") {
      return { block: true, reason: localRefusalText(verdict) };
    }
    deepFreeze(input);
    this.labels.set(toolCallId, labelsOf(toolName, resolved, rules!));
    return { block: false };
  }

  /** The read labels decided for an allowed call, once: they are forgotten as they are returned. */
  labelsFor(toolCallId: string): InfluenceClass[] | undefined {
    const out = this.labels.get(toolCallId);
    this.labels.delete(toolCallId);
    return out;
  }

  /** What the call would touch, as the tool would resolve it. Anything that throws is uncheckable. */
  private resolve(toolName: string, input: Record<string, unknown>, rules: LocalRules): Resolved {
    const ctx: PathContext = { cwd: this.deps.workspace, workspace: this.deps.workspace, rules, refused: this.deps.refused };
    try {
      if (toolName === "powershell") {
        return UNPARSED;
      }
      if (FILE_TOOLS.includes(toolName)) {
        return resolveFileTool(toolName as FileTool, input, ctx);
      }
      if (toolName === "bash") {
        return typeof input.command === "string" ? resolveBash(input.command, { ...ctx, pathDirs: PINNED_PATH.split(":") }) : UNPARSED;
      }
      // another extension's tool or pi's built-in MCP: no paths of its own, so only its route decides
      return NOTHING;
    } catch {
      return UNPARSED;
    }
  }
}

/**
 * The classes an allowed call's result records: the labels of the folders a read tool read, those
 * plus local-untrusted for bash (a program's output is not fully known), nothing for write and edit,
 * and local-untrusted for any other tool.
 */
function labelsOf(toolName: string, resolved: Resolved, rules: LocalRules): InfluenceClass[] {
  if (READ_TOOLS.includes(toolName)) {
    return readLabels(resolved, rules);
  }
  if (toolName === "bash") {
    return [...new Set<InfluenceClass>([...readLabels(resolved, rules), "local-untrusted"])];
  }
  if (toolName === "write" || toolName === "edit") {
    return [];
  }
  return ["local-untrusted"];
}
