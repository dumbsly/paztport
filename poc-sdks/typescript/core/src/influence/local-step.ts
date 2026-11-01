// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readToken, type JsonValue } from "../encoding/json.ts";
import { array, bool, exactly, object, str } from "../internal/fields.ts";
import { bindLocalTool } from "../stamp/binding.ts";
import { commitInfluence, type InfluenceEntry } from "./influence.ts";
import type { LocalVerdict, Need, Resolved, ResolvedProgram } from "./local-decision.ts";
import { signStamp, type Stamp } from "../stamp/stamp.ts";

/** What a local tool's receiver starts with: its route names `local:<tool>` after the client chain. */
export const LOCAL_RECEIVER_PREFIX = "local:";

/** The receiver a local tool call names, `local:<tool>`. */
export function localReceiver(tool: string): string {
  return LOCAL_RECEIVER_PREFIX + tool;
}

/** What a local step signs: the call, the gate's decision on it, and the step's place in the run's chain. */
export type LocalStepFields = {
  svc: string;
  inst: string;
  rid: string;
  ts: number;
  /** The signature of the run's origin stamp. */
  prev: string;
  toolName: string;
  toolCallId: string;
  /** The input as recorded in the evidence. */
  input: unknown;
  resolved: Resolved;
  verdict: LocalVerdict;
  /** Whether the session's route list has the tool. */
  listed: boolean;
  /** rulesHash of the rules that decided, null with none. */
  rulesHash: string | null;
  /** The influence the call was decided under. */
  influence: InfluenceEntry[];
};

/**
 * A local tool call as a signed client-mesh step: a v3 stamp with an empty `sess`, naming `local:<tool>` as its
 * receiver, bound to the input and the decision (the call id, what was resolved, the verdict, whether the route
 * is listed and which rules decided), so none of them can be changed in the evidence after signing.
 */
export function stampLocalStep(f: LocalStepFields, privateKey: string): Stamp {
  const bind = localStepBind(f);
  return signStamp(
    { svc: f.svc, inst: f.inst, rid: f.rid, ts: f.ts, sess: "", rcv: localReceiver(f.toolName), bind, infl: commitInfluence(f.influence), prev: f.prev },
    privateKey,
  );
}

/** The binding a local step's stamp carries: the call and the decision on it. Throws if the input can't be bound. */
export function localStepBind(f: Pick<LocalStepFields, "toolName" | "toolCallId" | "input" | "resolved" | "verdict" | "listed" | "rulesHash">): string {
  return bindLocalTool(f.toolName, f.input, {
    callId: f.toolCallId,
    resolved: f.resolved,
    verdict: f.verdict,
    routeAllowed: f.listed,
    rulesHash: f.rulesHash,
  });
}

/** The gate's decision on one local call, the object `localStepBind` hashes. */
export type LocalDecision = {
  callId: string;
  resolved: Resolved;
  verdict: LocalVerdict;
  routeAllowed: boolean;
  /** rulesHash of the rules that decided, null with none. */
  rulesHash: string | null;
};

const VERDICTS: readonly string[] = ["OK", "PATH_NOT_ALLOWED", "SCOPE_DENIED", "UNCHECKABLE", "INFLUENCE_DENIED"];
const NEEDS: readonly string[] = ["read", "write", "exec"];
const VIAS: readonly string[] = ["list", "folder", "never", "missing", "uncheckable"];

function resolvedOf(value: JsonValue): Resolved {
  const o = object(value);
  exactly(o, ["paths", "programs", "parse", "readOnly"]);
  const paths = array(o, "paths").map((item) => {
    const p = object(item);
    exactly(p, ["need", "at"]);
    const need = str(p, "need");
    if (!NEEDS.includes(need)) throw new Error("member need is not a need");
    return { need: need as Need, at: str(p, "at") };
  });
  const programs = array(o, "programs").map((item) => {
    const p = object(item);
    exactly(p, ["name", "via"]);
    const via = str(p, "via");
    if (!VIAS.includes(via)) throw new Error("member via is not a route to a program");
    return { name: str(p, "name"), via: via as ResolvedProgram["via"] };
  });
  const parse = str(o, "parse");
  if (parse !== "ok" && parse !== "error") throw new Error("member parse is not ok or error");
  return { paths, programs, parse, readOnly: bool(o, "readOnly") };
}

/**
 * Reads a local step's decision from its token: MalformedJson for bytes that do not read, an Error naming the
 * member for an object that is not exactly a decision.
 */
export function readLocalDecision(token: string): LocalDecision {
  const o = object(readToken(token));
  exactly(o, ["callId", "resolved", "verdict", "routeAllowed", "rulesHash"]);
  const verdict = str(o, "verdict");
  if (!VERDICTS.includes(verdict)) throw new Error("member verdict is not a verdict");
  const hash = o.rulesHash;
  if (hash !== null && typeof hash !== "string") throw new Error("member rulesHash is not a string or null");
  return {
    callId: str(o, "callId"),
    resolved: resolvedOf(o.resolved as JsonValue),
    verdict: verdict as LocalVerdict,
    routeAllowed: bool(o, "routeAllowed"),
    rulesHash: hash,
  };
}
