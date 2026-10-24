// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "./b64url.ts";
import { concat, sha256, utf8 } from "./crypto.ts";

const NL = new Uint8Array([0x0a]);

/** v1 request binding: SHA-256(method LF path LF body), base64url. */
export function bindHttp(method: string, path: string, body: Uint8Array): string {
  return encode(sha256(concat(utf8(method), NL, utf8(path), NL, body)));
}
