// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

/** Sink for verification events: logged, or POSTed to the responder. */
public interface EventPublisher {

    void publish(AttestationEvent event);
}
