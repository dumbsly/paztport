// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.paztport.core.influence.InfluenceEntry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * The PSP's record of the influence each call carried, per rid: the blinded entries the shop's boundary stamp
 * committed to and the partner filter verified. An opening the shop shows later is checked against these, so they
 * must be what the PSP actually decided on, the refused calls included.
 *
 * <p>A demo stand-in for the PSP's own audit log, which the demo does not build: in memory, holding only the
 * latest {@value #CAPACITY} requests so a long run cannot grow it without end, and only the last call of a rid,
 * since each of the shop's requests calls the PSP at most once in the demo. Enabled only when
 * {@code paztport.openings=true}.
 */
@Component
@ConditionalOnProperty(name = "paztport.openings", havingValue = "true")
public final class ReceivedInfluence {

    /** Enough for every request of a demo run several times over. */
    static final int CAPACITY = 1000;

    private final Map<String, List<InfluenceEntry>> received;

    public ReceivedInfluence() {
        this(CAPACITY);
    }

    ReceivedInfluence(int capacity) {
        // Request threads record concurrently, so every access goes through the synchronised view.
        this.received = Collections.synchronizedMap(new LinkedHashMap<>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, List<InfluenceEntry>> eldest) {
                return size() > capacity;
            }
        });
    }

    /** Records what a verified call of request {@code rid} carried. */
    public void record(String rid, List<InfluenceEntry> influence) {
        received.put(rid, List.copyOf(influence));
    }

    /** What the last verified call of {@code rid} carried, if this record still holds it. */
    public Optional<List<InfluenceEntry>> received(String rid) {
        return Optional.ofNullable(received.get(rid));
    }

    /** How many requests are held. */
    int size() {
        return received.size();
    }
}
