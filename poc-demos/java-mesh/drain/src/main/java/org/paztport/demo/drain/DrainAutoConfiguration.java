// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

/**
 * Wires the drain into a servlet application that depends on this module: the state, the lifecycle that holds the
 * close for {@code demo.drain-seconds} seconds (default 5, 0 for none), and the filter that marks the responses.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class DrainAutoConfiguration {

    @Bean
    DrainState drainState() {
        return new DrainState();
    }

    @Bean
    DrainLifecycle drainLifecycle(DrainState state, ApplicationContext context,
            @Value("${demo.drain-seconds:5}") long seconds) {
        return new DrainLifecycle(state, Duration.ofSeconds(seconds), context);
    }

    @Bean
    FilterRegistrationBean<ConnectionCloseFilter> connectionCloseFilter(DrainState state) {
        FilterRegistrationBean<ConnectionCloseFilter> registration =
                new FilterRegistrationBean<>(new ConnectionCloseFilter(state));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
