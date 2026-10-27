// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.ResponderEvent;

/**
 * The responder's brain, with no Docker in sight. Counts rejections per instance
 * in a sliding window and decides whether to quarantine, and a per-service
 * sliding window acts as a circuit breaker that escalates instead of acting once
 * a service has been quarantined too often.
 *
 * <p>Instances are counted under {@code svc/inst}. The instance name is chosen
 * by the service that signed it, so keying by it alone would let one service's
 * events build up a count against another service's instance.
 *
 * <p>Not thread-safe on its own; the event endpoint serialises calls.
 */
public final class QuarantineDecider {

    /**
     * Refusals of a sound chain because of what shaped it. The sender did nothing wrong in transit, so these are
     * the policy working, not evidence against an instance.
     */
    private static final Set<String> POLICY_REFUSALS = Set.of("INFLUENCE_DENIED", "UNSAFE_SESSION");

    private final QuarantineConfig config;
    private final LongSupplier clock;
    private final Map<String, Deque<Long>> rejectionsByInstance = new HashMap<>();
    private final Map<String, Deque<Long>> quarantinesByService = new HashMap<>();

    public QuarantineDecider(QuarantineConfig config, LongSupplier clock) {
        this.config = config;
        this.clock = clock;
    }

    public QuarantineDecision observe(ResponderEvent event) {
        if (event.audit() || POLICY_REFUSALS.contains(event.reason())
                || event.suspectInst() == null || event.suspectInst().isBlank()) {
            return QuarantineDecision.NONE;
        }
        long now = clock.getAsLong();

        Deque<Long> rejections = rejectionsByInstance.computeIfAbsent(
                event.suspectSvc() + "/" + event.suspectInst(), k -> new ArrayDeque<>());
        prune(rejections, now - config.windowMs());
        rejections.addLast(now);

        if (rejections.size() < config.threshold()) {
            return QuarantineDecision.NONE;
        }

        // Threshold reached: this instance has earned a quarantine. The instance
        // window resets either way so a single further event cannot re-trigger.
        rejections.clear();

        Deque<Long> quarantines = quarantinesByService.computeIfAbsent(event.suspectSvc(), k -> new ArrayDeque<>());
        prune(quarantines, now - config.svcWindowMs());
        if (quarantines.size() >= config.maxPerSvc()) {
            return QuarantineDecision.ESCALATE;
        }
        quarantines.addLast(now);
        return QuarantineDecision.QUARANTINE;
    }

    private static void prune(Deque<Long> stamps, long cutoff) {
        while (!stamps.isEmpty() && stamps.peekFirst() <= cutoff) {
            stamps.removeFirst();
        }
    }
}
