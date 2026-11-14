// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.paztport.core.stamp.Block;

/**
 * What a client requires of a server: the extensions it must act on, each once and sorted, and whether the client
 * goes on without them (the configuration switch). The rule of what it may do is {@link #callsAfter}, and its home
 * is spec sessions.md, "A client that requires extensions".
 */
public final class Requirement {

    /** A client that requires nothing. */
    public static final Requirement NONE = new Requirement(List.of(), false);

    private final List<String> extensions;
    private final boolean continueWithout;

    private Requirement(List<String> extensions, boolean continueWithout) {
        this.extensions = extensions;
        this.continueWithout = continueWithout;
    }

    /**
     * A client's requirement, built and checked once so that a bad configuration fails where it is read, not at the
     * first call's stamp.
     *
     * @param extensions the extensions the client requires of a server; each is held once, sorted
     * @param continueWithout whether the client goes on without them, as {@link #callsAfter} says
     * @throws IllegalArgumentException a name that is not an extension name
     */
    public static Requirement of(Set<String> extensions, boolean continueWithout) {
        TreeSet<String> sorted = new TreeSet<>();
        for (String name : extensions) {
            if (name == null || !Block.isExtensionName(name)) {
                throw new IllegalArgumentException("a name that is not an extension name");
            }
            sorted.add(name);
        }
        return new Requirement(List.copyOf(sorted), continueWithout);
    }

    /** The required extensions, sorted, each once; unmodifiable. */
    public List<String> extensions() {
        return extensions;
    }

    /** Whether the client makes calls though the server does not give it what it requires. */
    public boolean continueWithout() {
        return continueWithout;
    }

    /**
     * What this client may do in the session a handshake left it (sessions.md, "A client that requires
     * extensions"). Only an attested session whose reply lists every required name lets a client make calls under
     * its requirement, so neither a server answering "unsafe" nor anyone who can make the handshake fail switches
     * it off; only {@code continueWithout} does, and then a call carries no {@code requires} for a name the client
     * could not get.
     *
     * @param check the first reply's check, or null when no reply could be checked (an error, a timeout, no
     *        answer); a client that sent no handshake passes {@link ReplyCheck#UNSAFE}
     * @param listed that reply's extensions, empty when it did not read
     */
    public Calls callsAfter(ReplyCheck check, List<String> listed) {
        if (extensions.isEmpty()) {
            return new Calls(true, List.of());
        }
        if (check == ReplyCheck.ATTESTED) {
            return new Calls(true, extensions);
        }
        if (!continueWithout) {
            return new Calls(false, List.of());
        }
        if (check == ReplyCheck.EXTENSION_REQUIRED) {
            List<String> carried = new ArrayList<>();
            for (String name : extensions) {
                if (listed.contains(name)) {
                    carried.add(name);
                }
            }
            return new Calls(true, carried);
        }
        return new Calls(true, List.of());
    }

    /**
     * Whether the client makes calls, and the {@code requires} each call's block carries (wire.md, Blocks).
     *
     * @param calls whether the client makes calls in the session
     * @param requires the names each call's block requires; unmodifiable
     */
    public record Calls(boolean calls, List<String> requires) {

        public Calls {
            requires = List.copyOf(requires);
        }
    }
}
