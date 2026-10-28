// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

// The record of what each call carried, and the check against it, exist only when the flag is on.
class OpeningsWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(ReceivedInfluence.class, OpeningCheckController.class);

    @Test
    void presentWhenTheFlagIsOn() {
        runner.withPropertyValues("paztport.openings=true").run(context -> {
            assertEquals(1, context.getBeanNamesForType(ReceivedInfluence.class).length);
            assertEquals(1, context.getBeanNamesForType(OpeningCheckController.class).length);
        });
    }

    @Test
    void absentWhenTheFlagIsOff() {
        runner.run(context -> {
            assertEquals(0, context.getBeanNamesForType(ReceivedInfluence.class).length);
            assertEquals(0, context.getBeanNamesForType(OpeningCheckController.class).length);
        });
        runner.withPropertyValues("paztport.openings=false").run(context -> {
            assertEquals(0, context.getBeanNamesForType(ReceivedInfluence.class).length);
            assertEquals(0, context.getBeanNamesForType(OpeningCheckController.class).length);
        });
    }
}
