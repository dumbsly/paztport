// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.http.BoundaryListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * The shop's record of what each blinded entry it sent the PSP stood for: the originals the egress was told of,
 * per rid and partner. The PSP holds only salted commitments, so without these the shop could never show what a
 * refused request carried; the salt itself is not kept, since the egress's client derives it again.
 *
 * <p>A demo stand-in for where the shop keeps its evidence, which the demo does not build: in memory, holding only
 * the latest {@value #CAPACITY} requests so a long run cannot grow it without end, and only the last call of a rid
 * to a partner, since each of the demo's requests calls the PSP at most once (a sender whose requests may call one
 * partner again after the nonce window keeps every call's originals). Enabled only when
 * {@code paztport.openings=true}; as the egress's only {@link BoundaryListener}, it is then told of every attested
 * call before it goes. The originals are the shop's secrets, so nothing here logs them.
 */
@Component
@ConditionalOnProperty(name = "paztport.openings", havingValue = "true")
public final class BoundaryOpenings implements BoundaryListener {

    /** Enough for every request of a demo run several times over. */
    static final int CAPACITY = 1000;

    private record Key(String rid, String partner) {
    }

    private final Map<Key, List<InfluenceEntry>> originals;

    public BoundaryOpenings() {
        this(CAPACITY);
    }

    BoundaryOpenings(int capacity) {
        // Request threads call the listener concurrently, so every access goes through the synchronised view.
        this.originals = Collections.synchronizedMap(new LinkedHashMap<>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Key, List<InfluenceEntry>> eldest) {
                return size() > capacity;
            }
        });
    }

    @Override
    public void sent(String rid, String partnerEntry, List<InfluenceEntry> originals, List<InfluenceEntry> sent) {
        this.originals.put(new Key(rid, partnerEntry), List.copyOf(originals));
    }

    /** The originals of the last call request {@code rid} made to {@code partner}, if this store still holds them. */
    public Optional<List<InfluenceEntry>> originals(String rid, String partner) {
        return Optional.ofNullable(originals.get(new Key(rid, partner)));
    }
}
