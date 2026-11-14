// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.Set;
import org.paztport.core.stamp.Block;

/**
 * The extensions a service acts on and the names its verifier carries (spec verification.md, Inputs). It is built
 * here once, so a verifier never meets settings that break the rule that a service cannot act on an extension its
 * own list refuses.
 */
public final class ExtensionSettings {

    /** Acts on none, carries any name. */
    public static final ExtensionSettings NONE = new ExtensionSettings(Set.of(), null);

    private final Set<String> actsOn;
    private final Set<String> allowed;

    private ExtensionSettings(Set<String> actsOn, Set<String> allowed) {
        this.actsOn = actsOn;
        this.allowed = allowed;
    }

    /**
     * The settings for the given sets, copied.
     *
     * @param actsOn the extensions the service acts on
     * @param allowed the names the verifier carries; null is unset, and the verifier carries any name
     * @throws IllegalArgumentException a name that is not an extension name, or a name in {@code actsOn} that a
     *         non-null {@code allowed} does not hold
     */
    public static ExtensionSettings of(Set<String> actsOn, Set<String> allowed) {
        if (actsOn == null) {
            throw new IllegalArgumentException("extension settings: no actsOn set");
        }
        Set<String> acts = checked(actsOn);
        Set<String> carried = allowed == null ? null : checked(allowed);
        if (carried != null && !carried.containsAll(acts)) {
            throw new IllegalArgumentException("extension settings: a name in actsOn outside the allowed list");
        }
        return new ExtensionSettings(acts, carried);
    }

    private static Set<String> checked(Set<String> names) {
        for (String name : names) {
            if (name == null || !Block.isExtensionName(name)) {
                throw new IllegalArgumentException("extension settings: a name that is not an extension name");
            }
        }
        return Set.copyOf(names);
    }

    /** The extensions the service acts on; unmodifiable. */
    public Set<String> actsOn() {
        return actsOn;
    }

    /** The names the verifier carries; unmodifiable, or null when unset. */
    public Set<String> allowed() {
        return allowed;
    }

    /** Whether the verifier carries the name: true when the allowed list is unset or holds it. */
    public boolean carries(String name) {
        return allowed == null || allowed.contains(name);
    }
}
