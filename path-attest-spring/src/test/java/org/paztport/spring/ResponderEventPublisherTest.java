// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

class ResponderEventPublisherTest {

    @Test
    void publishIsBestEffortWhenResponderIsUnreachable() {
        // Port 1 refuses connections; publishing must never break verification.
        ResponderEventPublisher publisher = new ResponderEventPublisher("http://127.0.0.1:1");
        assertDoesNotThrow(() ->
                publisher.publish(new AttestationEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", false)));
    }
}
