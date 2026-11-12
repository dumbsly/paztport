// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * Wires the drain into a servlet application that depends on this module: the state, the lifecycle that holds the
 * close for {@code demo.drain-seconds} seconds (default 5, 0 for none), and, on Tomcat, the valve that marks the
 * responses {@code Connection: close}. The valve is in Tomcat, outside the servlet filter chain, so it covers every
 * response whatever the filters do. A connector limit of one request per connection would not do: Tomcat reads it
 * when a request starts, so a request in progress when the drain began would keep its connection. Nor would a valve
 * that only sets the header before and after the chain: Spring MVC commits the response inside the chain.
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
    @ConditionalOnClass(TomcatServletWebServerFactory.class)
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> drainTomcat(DrainState state) {
        return factory -> factory.addContextValves(new ConnectionCloseValve(state));
    }
}
