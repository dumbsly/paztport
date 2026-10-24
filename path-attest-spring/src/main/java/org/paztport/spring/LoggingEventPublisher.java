// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Logs each event as a single structured line. No key material or proofs are logged. */
public final class LoggingEventPublisher implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger("PATH_ATTEST_EVENT");

    @Override
    public void publish(AttestationEvent event) {
        log.warn(format(event));
    }

    static String format(AttestationEvent e) {
        return String.format(
                "PATH_ATTEST_EVENT reason=%s suspectSvc=%s suspectInst=%s rid=%s audit=%s",
                e.reason(), e.suspectSvc(), e.suspectInst(), e.rid(), e.audit());
    }
}
