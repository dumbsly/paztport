// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

/**
 * A request payment received, retained only for the demo's replay/mutate harness: its chain, proof and blocks
 * ({@code X-Path-Extensions}) headers as they arrived, any of them null when absent.
 */
public record CapturedRequest(
        String chainHeader, String proofHeader, String blocksHeader, String method, String path, byte[] body) {
}
