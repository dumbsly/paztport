// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.paztport.spring.partner.BoundaryListener;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

// The opening store, which is the egress's boundary listener, and its endpoint exist only when the flag is on.
class OpeningsWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withUserConfiguration(BoundaryOpenings.class, OpeningController.class);

    @Test
    void presentWhenTheFlagIsOn() {
        runner.withPropertyValues("paztport.openings=true", "paztport.boundary.partner=psp").run(context -> {
            assertEquals(1, context.getBeanNamesForType(BoundaryListener.class).length);
            assertEquals(1, context.getBeanNamesForType(OpeningController.class).length);
        });
    }

    @Test
    void absentWhenTheFlagIsOff() {
        runner.run(context -> {
            assertEquals(0, context.getBeanNamesForType(BoundaryListener.class).length);
            assertEquals(0, context.getBeanNamesForType(OpeningController.class).length);
        });
        runner.withPropertyValues("paztport.openings=false").run(context -> {
            assertEquals(0, context.getBeanNamesForType(BoundaryListener.class).length);
            assertEquals(0, context.getBeanNamesForType(OpeningController.class).length);
        });
    }
}
