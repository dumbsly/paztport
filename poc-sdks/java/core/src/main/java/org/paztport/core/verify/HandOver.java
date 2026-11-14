// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;

/**
 * What a service is handed for the extensions it acts on (spec verification.md, The live order): for each name in
 * the settings' {@code actsOn}, one entry per stamp in chain order. It says whether the chain passed the verifier's
 * whole order; a request served without verifying is handed one that is not verified.
 */
public final class HandOver {

    /** One stamp's entry: its signer, and the items its block holds under the name, null when it does not name it. */
    public record StampItems(String svc, List<String> items) {
    }

    private final boolean verified;
    private final Map<String, List<StampItems>> byName;

    /**
     * @param verified whether the chain passed the verifier's whole order; false for a request served without
     *        verifying
     * @param stamps the chain's stamps, in order
     * @param blocks the stamps' blocks, the same length as {@code stamps}
     * @param settings the extensions the service acts on
     * @throws IllegalArgumentException stamps and blocks of different lengths
     */
    public HandOver(boolean verified, List<Stamp> stamps, List<Block> blocks, ExtensionSettings settings) {
        if (stamps.size() != blocks.size()) {
            throw new IllegalArgumentException("hand-over: " + stamps.size() + " stamps but " + blocks.size()
                    + " blocks");
        }
        this.verified = verified;
        Map<String, List<StampItems>> map = new TreeMap<>();
        for (String name : settings.actsOn()) {
            List<StampItems> entries = new ArrayList<>();
            for (int i = 0; i < stamps.size(); i++) {
                List<String> items = blocks.get(i).itemsUnder(name);
                entries.add(new StampItems(stamps.get(i).svc(), items == null ? null : List.copyOf(items)));
            }
            map.put(name, List.copyOf(entries));
        }
        this.byName = Map.copyOf(map);
    }

    /**
     * The rule a verifier's result keeps (spec verification.md, The live order: "On OK the verifier hands the
     * service..."): a hand-over exactly when {@code reason} is OK, and then one that is verified; a refusal hands
     * nothing over. The live and the offline results both call it.
     *
     * @throws IllegalArgumentException a hand-over on a reason other than OK, none on OK, or one not verified
     */
    public static void requireFor(ReasonCode reason, HandOver handOver) {
        if ((reason == ReasonCode.OK) != (handOver != null) || (handOver != null && !handOver.verified)) {
            throw new IllegalArgumentException("a verifier hands over a verified hand-over exactly on OK");
        }
    }

    /** Whether the chain passed the verifier's whole order here; false for a request served without verifying. */
    public boolean verified() {
        return verified;
    }

    /** The extension names the service acts on; unmodifiable. */
    public Set<String> names() {
        return byName.keySet();
    }

    /** One entry per stamp, in chain order; null when the service does not act on the name. Unmodifiable. */
    public List<StampItems> under(String name) {
        return byName.get(name);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof HandOver h && verified == h.verified && byName.equals(h.byName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(verified, byName);
    }

    @Override
    public String toString() {
        return "HandOver[verified=" + verified + ", " + byName + "]";
    }
}
