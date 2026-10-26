// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.concurrent.Executor;
import org.paztport.core.ResponderEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Applies the decider's verdict: quarantine the offending instance, or log an
 * escalation when the circuit breaker trips.
 *
 * <p>The quarantine action runs on the supplied {@link Executor}, not inline:
 * the suspect is part of the request chain that produced this event, so
 * disconnecting it from the mesh synchronously would sever the triggering
 * request before it could get its response. Returning the decision immediately
 * lets that chain unwind first.
 */
public final class ResponderService {

    private static final Logger log = LoggerFactory.getLogger(ResponderService.class);

    private final QuarantineDecider decider;
    private final Quarantiner quarantiner;
    private final Executor executor;

    public ResponderService(QuarantineDecider decider, Quarantiner quarantiner, Executor executor) {
        this.decider = decider;
        this.quarantiner = quarantiner;
        this.executor = executor;
    }

    public synchronized QuarantineDecision handle(ResponderEvent event) {
        QuarantineDecision decision = decider.observe(event);
        switch (decision) {
            case QUARANTINE -> {
                log.warn("QUARANTINE svc={} inst={} reason={}",
                        LogSafe.of(event.suspectSvc()), LogSafe.of(event.suspectInst()), LogSafe.of(event.reason()));
                executor.execute(() -> quarantiner.quarantine(event.suspectSvc(), event.suspectInst()));
            }
            case ESCALATE -> log.error("ESCALATE svc={} inst={} — per-service quarantine limit exceeded, paging a human",
                    LogSafe.of(event.suspectSvc()), LogSafe.of(event.suspectInst()));
            case NONE -> {
                // below threshold, audit, or unattributable: nothing to do
            }
        }
        return decision;
    }
}
