// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.event;

import java.time.Duration;

/**
 * Test access to what the responder publisher was built with. The auto-configuration's tests, in the root package,
 * check the event timeout the starter gave it; the accessor stays package-private in
 * {@link ResponderEventPublisher}, so this lives in its package for that reason only.
 */
public final class EventAccess {

    private EventAccess() {
    }

    /** The publisher's event timeout, as {@code paztport.event-timeout-ms} set it. */
    public static Duration timeout(ResponderEventPublisher publisher) {
        return publisher.timeout();
    }
}
