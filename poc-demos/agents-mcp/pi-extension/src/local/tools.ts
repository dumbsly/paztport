// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { LocalToolKind } from "@paztport/core";

/** pi's built-in local tools. */
export const BUILTIN_LOCAL_TOOLS = ["read", "write", "edit", "bash", "grep", "find", "ls", "powershell"] as const;

export type BuiltinLocalTool = (typeof BUILTIN_LOCAL_TOOLS)[number];

const KINDS: Record<BuiltinLocalTool, LocalToolKind> = {
  read: "read",
  write: "write",
  edit: "write",
  bash: "exec",
  grep: "read",
  find: "read",
  ls: "read",
  powershell: "exec",
};

/** What a pi tool does; any tool that is not one of pi's built-ins (another extension's, pi's MCP) is "other". */
export function toolKind(toolName: string): LocalToolKind {
  return Object.hasOwn(KINDS, toolName) ? KINDS[toolName as BuiltinLocalTool] : "other";
}
