// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import org.paztport.spring.PartnerFilter;

/**
 * The values of {@link PartnerFilter#SESSION_STATUS}: the partner's filter sets one on every request and its gate
 * reads it, so both take them from here. It is not for an application to use.
 */
public final class SessionStatus {

    public static final String ATTESTED = "attested";
    public static final String UNSAFE = "unsafe";

    private SessionStatus() {
    }
}
