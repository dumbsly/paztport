// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class VerificationModeTest {

    @Test
    void parsesKnownModesCaseInsensitively() {
        assertEquals(VerificationMode.OFF, VerificationMode.fromProperty("off"));
        assertEquals(VerificationMode.AUDIT, VerificationMode.fromProperty("AUDIT"));
        assertEquals(VerificationMode.ENFORCE, VerificationMode.fromProperty("Enforce"));
    }

    @Test
    void defaultsToEnforceForNullBlankOrUnknown() {
        // Fail closed: anything we do not recognise is the most restrictive mode.
        assertEquals(VerificationMode.ENFORCE, VerificationMode.fromProperty(null));
        assertEquals(VerificationMode.ENFORCE, VerificationMode.fromProperty(""));
        assertEquals(VerificationMode.ENFORCE, VerificationMode.fromProperty("banana"));
    }

    @Test
    void modeHolderIsMutable() {
        ModeHolder holder = new ModeHolder(VerificationMode.ENFORCE);
        assertEquals(VerificationMode.ENFORCE, holder.get());
        holder.set(VerificationMode.AUDIT);
        assertEquals(VerificationMode.AUDIT, holder.get());
    }
}
