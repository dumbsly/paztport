// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import org.paztport.core.verify.VerifyResult;

/**
 * The fixed words the starter's observations use as tag values, besides a reason code's name: the filters and the
 * interceptor take them from here, so the same word means the same thing in each. It is not for an application to
 * use.
 */
public final class ObservedValues {

    /** No value: a mode where requests are not verified, or a reason where no verification result is available. */
    public static final String NONE = "none";
    /** A request that went on to its handler. */
    public static final String SERVED = "served";
    /** A request answered with a refusal in place of its handler. */
    public static final String REFUSED = "refused";
    /** A partner's call in an attested session. */
    public static final String ATTESTED = "attested";
    /** A partner's call in an unsafe session. */
    public static final String UNSAFE = "unsafe";
    /** A partner's call naming a session its peer does not hold. */
    public static final String UNKNOWN = "unknown";

    private ObservedValues() {
    }

    /** The name of the reason {@code result} gave, or {@link #NONE} where it is null. */
    public static String reason(VerifyResult result) {
        return result == null ? NONE : result.reason().name();
    }
}
