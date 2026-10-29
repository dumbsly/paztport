// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.event;

/**
 * A verification verdict worth reporting. {@code audit} marks events produced in
 * audit mode; the responder ignores those.
 */
public record AttestationEvent(
        String reason, String suspectSvc, String suspectInst, String rid, boolean audit) {
}
