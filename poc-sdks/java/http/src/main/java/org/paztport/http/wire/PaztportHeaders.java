// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

/** The wire header names. */
public final class PaztportHeaders {

    public static final String CHAIN = "X-Path-Chain";
    public static final String PROOF = "X-Path-Proof";
    /** v3 only: the influence entries a request commits to. */
    public static final String INFLUENCE = "X-Path-Influence";
    /** v3 only: a response's attestation stamp and content labels. */
    public static final String RESPONSE = "X-Path-Response";

    /** v3 only: the id of the session a call to a partner organisation is made in. */
    public static final String SESSION = "X-Path-Session";

    private PaztportHeaders() {
    }
}
