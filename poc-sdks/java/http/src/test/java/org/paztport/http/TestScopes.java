// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;

/**
 * For tests that open a {@link RequestContext.Scope} by hand: what only {@link RequestContext#accept} may do with a
 * scope, set the service's extension settings and mark a chain verified at this hop. A scope opened without a receiver
 * has no settings, so a service acting on nothing, and {@link PublicWrites} denies every guarded write in it (spec
 * influence.md, The every-stamp rule): a guard that read nothing would otherwise hold vacuously. These stand in for
 * the receiver in a test. Both work only inside an open scope; the package-private methods they call stay so in main
 * code, and this class ships in the test jar, never in the library.
 */
public final class TestScopes {

    private TestScopes() {
    }

    /** Sets the settings of the service serving the open scope, as the receiver does once it has decided them. */
    public static void actOn(ExtensionSettings settings) {
        RequestContext.actOn(settings);
    }

    /**
     * Marks {@code chain} verified at this hop and sets what was handed on, as the receiver does after an
     * {@code OK}.
     *
     * @throws IllegalArgumentException when {@code handOver} is not verified; nothing is set
     */
    public static void verified(List<Stamp> chain, HandOver handOver) {
        if (!handOver.verified()) {
            throw new IllegalArgumentException("a hand-over that is not verified cannot stand for a verified chain");
        }
        RequestContext.markVerified(chain);
        RequestContext.handOn(handOver);
    }
}
