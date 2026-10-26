// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

/** Sink for verification events. Phase 5 adds an implementation that POSTs to the responder. */
public interface EventPublisher {

    void publish(AttestationEvent event);
}
