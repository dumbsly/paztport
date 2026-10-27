// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

/** A request payment received, retained only for the demo's replay/mutate harness. */
public record CapturedRequest(
        String chainHeader, String proofHeader, String influenceHeader, String method, String path, byte[] body) {
}
