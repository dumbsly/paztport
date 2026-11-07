// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

// The attack endpoints sign as orders and send payment calls no honest orders makes, so nothing of them may exist
// unless the demo turns them on.
class AttackControllerTest {

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(AttackController.class, StolenChainStore.class);

    @Test
    void theAttackEndpointsAreOffByDefault() {
        context.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(AttackController.class);
            assertThat(ctx).doesNotHaveBean(StolenChainStore.class);
        });
    }

    // The condition is the property, not a class that is never registered: enabled, the store is there.
    @Test
    void enablingThemCreatesTheStore() {
        new ApplicationContextRunner()
                .withUserConfiguration(StolenChainStore.class)
                .withPropertyValues("attack.enabled=true")
                .run(ctx -> assertThat(ctx).hasSingleBean(StolenChainStore.class));
    }
}
