// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * A stamp as it is read back from a chain: v3 (current) or v2 (legacy, read-only). The sealed pair lets a
 * verifier switch exhaustively on the version, and keeps a v2 stamp from ever acquiring a receiver by accident:
 * {@link #rcvOrNull()} is null for v2.
 */
public sealed interface RecordedStamp permits StampV2, StampV3 {

    String svc();

    String inst();

    String rid();

    long ts();

    String sess();

    String bind();

    String infl();

    String prev();

    String sig();

    /** The bytes the stamp's signature covers, by its version. */
    byte[] signingBytes();

    /** The signed receiver of a v3 stamp; null for v2, which has none. */
    String rcvOrNull();
}
