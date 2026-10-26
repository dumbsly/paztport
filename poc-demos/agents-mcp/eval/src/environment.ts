// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { arch, cpus, platform, release, totalmem } from "node:os";
import type { ModelRef } from "./models.ts";

/** What the eval ran on. `ollama` is present only for an ollama model; a value that could not be read is null. */
export type Environment = {
  os: { platform: string; release: string };
  arch: string;
  cpu: string | null;
  /** Total memory in GB, rounded. */
  memoryGb: number;
  node: string;
  /**
   * `contextLength` is the context window Ollama gives the model, when it can be read: the model's num_ctx
   * parameter, else OLLAMA_CONTEXT_LENGTH as set where the eval ran (Ollama uses that only if it was started
   * with the same setting). null when neither is known; Ollama's own default then applies.
   * Absent in folders written before it was recorded.
   */
  ollama?: { version: string | null; digest: string | null; contextLength?: { tokens: number; source: string } | null };
};

const OLLAMA = "http://127.0.0.1:11434";

async function getJson(f: typeof fetch, path: string, body?: unknown): Promise<unknown> {
  try {
    const init: RequestInit = { signal: AbortSignal.timeout(2000) };
    if (body !== undefined) Object.assign(init, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const res = await f(`${OLLAMA}${path}`, init);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

const positiveInt = (s: string | undefined): number | undefined => (s !== undefined && /^\d+$/.test(s.trim()) && Number(s) > 0 ? Number(s) : undefined);

/** Reads the machine, and for an ollama model asks Ollama for its version, the model's digest and its context length. Never throws. */
export async function collectEnvironment(model: ModelRef, fetchImpl: typeof fetch = fetch): Promise<Environment> {
  const env: Environment = {
    os: { platform: platform(), release: release() },
    arch: arch(),
    cpu: cpus()[0]?.model ?? null,
    memoryGb: Math.round(totalmem() / 2 ** 30),
    node: process.version,
  };
  if (model.provider !== "ollama") return env;
  const v = (await getJson(fetchImpl, "/api/version")) as { version?: unknown } | null;
  const tags = (await getJson(fetchImpl, "/api/tags")) as { models?: { name?: unknown; model?: unknown; digest?: unknown }[] } | null;
  const want = model.id.includes(":") ? model.id : `${model.id}:latest`;
  const entry = Array.isArray(tags?.models) ? tags.models.find((m) => m && (m.name === want || m.model === want)) : undefined;
  const show = (await getJson(fetchImpl, "/api/show", { model: model.id })) as { parameters?: unknown } | null;
  const numCtx = typeof show?.parameters === "string" ? positiveInt(/^num_ctx\s+(\d+)\s*$/m.exec(show.parameters)?.[1]) : undefined;
  const fromEnv = positiveInt(process.env.OLLAMA_CONTEXT_LENGTH);
  env.ollama = {
    version: typeof v?.version === "string" ? v.version : null,
    digest: typeof entry?.digest === "string" ? entry.digest : null,
    contextLength:
      numCtx !== undefined
        ? { tokens: numCtx, source: "the model's num_ctx parameter" }
        : fromEnv !== undefined
          ? { tokens: fromEnv, source: "OLLAMA_CONTEXT_LENGTH in the eval's environment" }
          : null,
  };
  return env;
}
