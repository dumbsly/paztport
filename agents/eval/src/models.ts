// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** A pi model, parsed from "provider/id". */
export type ModelRef = { provider: string; id: string };

const OLLAMA_HOST = "127.0.0.1:11434";

/** Splits at the first slash, so an id may hold more ("ollama/hf.co/org/model"). */
export function parseModel(s: string): ModelRef {
  const i = s.indexOf("/");
  if (i <= 0 || i === s.length - 1) throw new Error(`model must be written provider/id, for example ollama/qwen3:4b (got "${s}")`);
  return { provider: s.slice(0, i), id: s.slice(i + 1) };
}

function readModels(file: string): { providers?: Record<string, { models?: { id: string }[] }> } & Record<string, unknown> {
  try {
    const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
    if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) return raw as Record<string, unknown>;
  } catch {
    // no file yet, or one we replace
  }
  return {};
}

/**
 * Makes `dir` usable as pi's PI_CODING_AGENT_DIR for this model. For ollama it writes (or extends) the
 * dir's models.json. Any other provider needs the user's own dir (`userAgentDir`), which is left alone.
 */
export function prepareAgentDir(dir: string, model: ModelRef, userAgentDir = false): void {
  if (userAgentDir) return;
  if (model.provider !== "ollama") {
    throw new Error(`Provider ${model.provider} needs your own pi setup: pass --agent-dir <your pi agent directory>.`);
  }
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "models.json");
  const current = readModels(file);
  const providers = { ...(current.providers ?? {}) };
  const models = [...(providers.ollama?.models ?? [])];
  if (!models.some((m) => m.id === model.id)) models.push({ id: model.id });
  providers.ollama = { baseUrl: "http://127.0.0.1:11434/v1", api: "openai-completions", apiKey: "ollama", models } as (typeof providers)[string];
  const next = { $schema: "https://pi.dev/schemas/models.schema.json", ...current, providers };
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(next, null, 2) + "\n");
  renameSync(tmp, file);
}

/** For ollama, checks the server answers and has the model; throws a one-line message. Other providers: no check. */
export async function checkModelAvailable(model: ModelRef, fetchImpl: typeof fetch = fetch): Promise<void> {
  if (model.provider !== "ollama") return;
  const unreachable = new Error(`Ollama isn't reachable at ${OLLAMA_HOST}. Start it with \`ollama serve\`.`);
  let names: string[];
  try {
    const res = await fetchImpl(`http://${OLLAMA_HOST}/api/tags`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) throw unreachable;
    const body = (await res.json()) as { models?: { name?: string; model?: string }[] };
    names = (body.models ?? []).flatMap((m) => [m.name, m.model]).filter((x): x is string => typeof x === "string");
  } catch {
    throw unreachable;
  }
  const want = model.id.includes(":") ? model.id : `${model.id}:latest`;
  if (!names.includes(want)) throw new Error(`Model ${model.id} isn't pulled. Run \`ollama pull ${model.id}\`.`);
}
