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
  ollama?: { version: string | null; digest: string | null };
};

const OLLAMA = "http://127.0.0.1:11434";

async function getJson(f: typeof fetch, path: string): Promise<unknown> {
  try {
    const res = await f(`${OLLAMA}${path}`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Reads the machine, and for an ollama model asks Ollama for its version and the model's digest. Never throws. */
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
  env.ollama = {
    version: typeof v?.version === "string" ? v.version : null,
    digest: typeof entry?.digest === "string" ? entry.digest : null,
  };
  return env;
}
