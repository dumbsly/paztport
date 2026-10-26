// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { canonicalize, encode, sha256, utf8 } from "@paztport/core";

/** v2 MCP tools/call binding over tool name, call id and canonical arguments. */
export function bindMcpCall(toolName: string, toolCallId: string, args: unknown): string {
  if (toolName.includes("\n") || toolCallId.includes("\n")) {
    throw new Error("toolName and toolCallId must not contain newlines");
  }
  return encode(sha256(utf8(`tools/call\n${toolName}\n${toolCallId}\n${canonicalize(args ?? {})}`)));
}
