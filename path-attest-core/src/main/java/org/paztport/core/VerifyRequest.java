// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * Everything the verifier needs about the request it received: the two header
 * strings (either may be null) and the request line plus body it will rebind.
 */
public record VerifyRequest(String chainHeader, String proofHeader, String method, String path, byte[] body) {
}
