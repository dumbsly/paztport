// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

/**
 * What the offline verifier is handed for one recorded chain; the live input's fields, with the nonce key and
 * no peer, since a record has no transport. As there, {@code stamps}, {@code influence} and {@code proof} are JSON
 * text as recorded, read only by the verifier. {@code rid} is the one the record files the chain under (the
 * origin's when null); {@code recordedTs} null compares no time; {@code prompt} is the run's recorded prompt,
 * null when the run has none or it is in dispute, which the origin can then never bind.
 */
public record OfflineInput(
        String stamps,
        String expectedBind,
        String influence,
        String proof,
        String receiver,
        boolean receiverInRoute,
        String nonceKey,
        String rid,
        RecordedTimes recordedTs,
        String prompt) {
}
