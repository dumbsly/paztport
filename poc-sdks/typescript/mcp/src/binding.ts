// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { canonicalize, encode, sha256, utf8 } from "@paztport/core";

/** MCP tools/call binding over tool name, call id and canonical arguments. */
export function bindMcpCall(toolName: string, callId: string, args: unknown): string {
  if (toolName.includes("\n") || callId.includes("\n")) {
    throw new Error("toolName and callId must not contain newlines");
  }
  return encode(sha256(utf8(`tools/call\n${toolName}\n${callId}\n${canonicalize(args ?? {})}`)));
}
