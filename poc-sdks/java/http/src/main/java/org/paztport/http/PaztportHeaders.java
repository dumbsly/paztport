// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

/** The wire header names. */
public final class PaztportHeaders {

    public static final String CHAIN = "X-Path-Chain";
    public static final String PROOF = "X-Path-Proof";
    /** v3 only: the influence entries a request commits to. */
    public static final String INFLUENCE = "X-Path-Influence";
    /** v3 only: a response's attestation stamp and content labels. */
    public static final String RESPONSE = "X-Path-Response";

    private PaztportHeaders() {
    }
}
