// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The local gate: every tool call that is not one of this extension's MCP tools is checked here, in
// pi's tool_call hook, against the signed client rules before it runs.

import { homedir } from "node:os";
import {
  decideLocalCall,
  earliestNotAfter,
  influenceClasses,
  localReceiver,
  NOTHING_RESOLVED,
  resultLabels,
  routeOf,
  rulesHash,
  stampLocalStep,
  type InfluenceClass,
  type LocalRules,
  type LocalVerdict,
  type Resolved,
} from "@paztport/core";
import type { ExtensionMode } from "../config.ts";
import type { EventLog } from "../events.ts";
import type { EvidenceLog } from "../evidence.ts";
import type { InfluenceStore } from "../influence.ts";
import { CLIENT_CHAIN, PI_SVC, type ClientMaterial } from "../keys.ts";
import { localRefusalText, POLICY_EXPIRED_TEXT, SCOPE_TEXT } from "../refusals.ts";
import type { RunState } from "../runs.ts";
import { PINNED_PATH, resolveBash } from "./bash.ts";
import { canonical, resolveFileTool, type PathContext } from "./paths.ts";
import { encodePlaceholders } from "./placeholders.ts";
import { BUILTIN_LOCAL_TOOLS, toolKind, type BuiltinLocalTool } from "./tools.ts";

export { BUILTIN_LOCAL_TOOLS };

type FileTool = Exclude<BuiltinLocalTool, "bash" | "powershell">;
const FILE_TOOLS: readonly string[] = BUILTIN_LOCAL_TOOLS.filter((t): t is FileTool => t !== "bash" && t !== "powershell");
const INST = "pi-1";

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
 * run is a signed client-mesh step: a v3 stamp with an empty `sess`, naming `local:<tool>` as its receiver,
 * chained from the run's origin and bound to the input and the decision (the call id, what the gate resolved,
 * the verdict, whether the route is listed and the rules' hash), written to the evidence file with the route
 * proof and the influence. The input is bound and recorded with the workspace and home folder paths replaced
 * by "<workspace>" and "<home>" (encodePlaceholders, reversible); the tool runs with the input as given.
 * no-root mode has no rules to check against and refuses every call.
 * off mode allows everything and records nothing.
 *
 * Once the root the rules come from, or the keyring whose keys sign the steps, is past its notAfter, enforce mode
 * refuses every call POLICY_EXPIRED with an event only, before resolving anything: rules no current root covers are
 * not applied, and nothing is signed with material an offline verifier would no longer accept. It relies on the
 * windows loadClientMaterial verified at startup and on the injected clock.
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
    const emit = (verdict: LocalVerdict | "POLICY_EXPIRED") =>
      events.emit({ type: "local", tool: toolName, callId: toolCallId, ...(run !== undefined ? { rid: run.rid } : {}), verdict });
    if (mode === "no-root" || run === undefined) {
      // no rules to check against, or no user prompt to chain from: nothing is signed
      emit("SCOPE_DENIED");
      return { block: true, reason: localRefusalText("SCOPE_DENIED") };
    }
    const now = this.deps.now();
    const notAfter = earliestNotAfter(material.signedRoot.notAfter, material.keyringNotAfter);
    if (!(now <= notAfter)) {
      emit("POLICY_EXPIRED");
      return { block: true, reason: POLICY_EXPIRED_TEXT };
    }

    const route = routeOf([...CLIENT_CHAIN, localReceiver(toolName)]);
    const proof = Object.hasOwn(material.proofs, route) ? material.proofs[route]! : null;
    const entries = influence.entries();
    const rules = material.rules;
    const decided = decideLocalCall({
      routeAllowed: proof !== null,
      rules: rules ?? null,
      classes: influenceClasses(entries),
      resolve: () => this.resolve(toolName, input, rules!),
    });
    const resolved = decided.resolved;
    let verdict: LocalVerdict = decided.verdict;

    try {
      const origin = runs.origin("", material.sessionKey, INST);
      const routeAllowed = proof !== null;
      const hash = rules !== undefined ? rulesHash(rules) : null;
      const signedInput = encodePlaceholders(input, { workspace: spellings(this.deps.workspace), home: spellings(this.deps.home ?? homedir()) });
      const stamp = stampLocalStep(
        {
          svc: PI_SVC,
          inst: INST,
          rid: run.rid,
          ts: now,
          prev: origin.sig,
          toolName,
          toolCallId,
          input: signedInput,
          resolved,
          verdict,
          listed: routeAllowed,
          rulesHash: hash,
          influence: entries,
        },
        material.piKey,
      );
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
      // a call that cannot be bound or signed (input JCS rejects, a tool name that cannot be bound) is refused unsigned
      verdict = "UNCHECKABLE";
    }
    emit(verdict);
    if (verdict !== "OK") {
      return { block: true, reason: localRefusalText(verdict) };
    }
    deepFreeze(input);
    this.labels.set(toolCallId, resultLabels(toolKind(toolName), resolved, rules!));
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
      return NOTHING_RESOLVED;
    } catch {
      return UNPARSED;
    }
  }
}
