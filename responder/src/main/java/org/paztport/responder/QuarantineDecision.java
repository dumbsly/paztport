// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

/** What the decider concluded for one event. */
public enum QuarantineDecision {
    /** Nothing to do. */
    NONE,
    /** Isolate and replace the offending instance. */
    QUARANTINE,
    /** The service tripped too often; stop acting and page a human. */
    ESCALATE
}
