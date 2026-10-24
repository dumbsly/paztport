// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

/** The rejection event payment POSTs to the responder. Mirrors the verifier's verdict. */
public record ResponderEvent(String reason, String suspectSvc, String suspectInst, String rid, boolean audit) {
}
