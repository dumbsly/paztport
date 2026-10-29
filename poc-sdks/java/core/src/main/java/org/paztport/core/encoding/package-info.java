// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The byte forms on the wire: base64url, RFC 8785 canonical JSON, and the check that keeps a lone surrogate out
 * of anything signed. Each refuses what it cannot represent exactly, so both SDKs sign and hash the same bytes.
 */
package org.paztport.core.encoding;
