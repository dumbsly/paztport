// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { Scenario } from "../../mock-github-mcp/src/scenario.ts";
import { callPhrase } from "./steps.ts";

/**
 * What a run is doing right now, for the line under the timer. It is worked out from pi's `--mode json` events
 * and holds only a fixed label or a call's plain step phrase: never the model's thinking or answer text, partial
 * tool arguments or tool results.
 */
export type ActivityState = "starting" | "thinking" | "writing" | "calling" | "waiting" | "finished";
export type Activity = { state: ActivityState; label: string };
export type Tally = { leaked: number; blocked: number; resisted: number; other: number };

export const ACTIVITY: Record<ActivityState, string> = {
  starting: "Starting pi and the mock GitHub server…",
  thinking: "The model is thinking…",
  writing: "The model is writing its answer…",
  calling: "Calling a tool…",
  waiting: "Waiting for the mock GitHub server's reply…",
  finished: "Run finished",
};

const of = (state: ActivityState): Activity => ({ state, label: ACTIVITY[state] });
export const STARTING: Activity = of("starting");
export const FINISHED: Activity = of("finished");

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

export const sameActivity = (a: Activity, b: Activity): boolean => a.state === b.state && a.label === b.label;

/** `prev` itself when nothing changes, so a caller can send only the changes. */
function moveTo(prev: Activity, next: Activity): Activity {
  return sameActivity(prev, next) ? prev : next;
}

/** The activity after one pi `--mode json` event. Anything it does not recognise leaves the activity as it was. */
export function nextActivity(prev: Activity, event: unknown, scenario: Scenario): Activity {
  if (prev.state === "finished" || !isObj(event)) return prev;
  switch (event.type) {
    case "turn_start":
      return moveTo(prev, of("thinking"));
    case "message_start":
      return isObj(event.message) && event.message.role === "assistant" ? moveTo(prev, of("thinking")) : prev;
    case "tool_execution_start":
      return moveTo(prev, of("waiting"));
    case "agent_settled":
      return FINISHED;
    case "message_update": {
      const a = event.assistantMessageEvent;
      if (!isObj(a)) return prev;
      if (a.type === "thinking_start" || a.type === "thinking_delta") return moveTo(prev, of("thinking"));
      if (a.type === "text_start" || a.type === "text_delta") return moveTo(prev, of("writing"));
      if (a.type === "toolcall_start") return moveTo(prev, of("calling"));
      if (a.type === "toolcall_end") {
        const call = isObj(a.toolCall) ? a.toolCall : {};
        const phrase = typeof call.name === "string" && isObj(call.arguments) ? callPhrase(scenario, call.name, call.arguments) : undefined;
        return moveTo(prev, phrase === undefined ? of("calling") : { state: "calling", label: `Calling: ${phrase}…` });
      }
      return prev;
    }
    default:
      return prev;
  }
}

/** Where a run is in an eval, for example "Run 12 of 100 · Paztport on, run 3". */
export function runWhere(n: number, planned: number, modeLabel: string, index: number): string {
  return `Run ${n} of ${planned} · ${modeLabel}, run ${index}`;
}

/** The line as the page shows it, before the time in this state. */
export function activityText(a: Activity, where?: string): string {
  return where === undefined ? a.label : `${where} — ${a.label}`;
}

/** The classes so far, as the summary names them; other is timeout, error and no tool calls together. */
export function tallyOf(runs: unknown): Tally {
  const t: Tally = { leaked: 0, blocked: 0, resisted: 0, other: 0 };
  if (!Array.isArray(runs)) return t;
  for (const r of runs) {
    const o = isObj(r) ? r.outcome : undefined;
    if (o === "leaked") t.leaked++;
    else if (o === "blocked" || o === "blocked-with-private-text") t.blocked++;
    else if (o === "resisted") t.resisted++;
    else if (o === "timeout" || o === "error" || o === "no-tool-calls") t.other++;
  }
  return t;
}
