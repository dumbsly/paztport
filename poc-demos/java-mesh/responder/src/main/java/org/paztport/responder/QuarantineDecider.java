// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.event.ResponderEvent;

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
 * <p>The protocol spec's rule for which events may lead to action is narrower than this one, and fails closed:
 * {@code audit} false, both suspect fields non-empty, and a reason from its list of thirteen codes
 * ({@code poc-sdks/spec/wire.md}, "The event"). This class keeps the demo's deny-list until the decision moves
 * into the SDK's core, which will follow the spec. Every event the Java SDK sends meets both rules alike, since its
 * verifier never sends the other reasons; the one difference it can send, a peer certificate with no single
 * common name, names an empty service, and the instance check before quarantine refuses that.
 *
 * <p>Not thread-safe on its own; the event endpoint serialises calls.
 */
public final class QuarantineDecider {

    /**
     * Refusals that are not the sender's doing. {@code INFLUENCE_DENIED} and {@code UNSAFE_SESSION} refuse a sound
     * chain because of what shaped it: the policy working, not evidence against an instance. {@code POLICY_EXPIRED}
     * is the verifier's own pinned policy running out, which every honest caller meets; the verifier names no
     * suspect for it, and this list keeps it out even if an event ever named one.
     */
    private static final Set<String> POLICY_REFUSALS = Set.of("INFLUENCE_DENIED", "UNSAFE_SESSION", "POLICY_EXPIRED");

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
