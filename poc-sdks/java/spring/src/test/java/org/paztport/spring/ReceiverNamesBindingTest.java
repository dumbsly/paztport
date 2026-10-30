// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.support.SpringApplicationJsonEnvironmentPostProcessor;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/**
 * How Spring Boot binds {@code paztport.receiver-names} keys a host cannot be written plainly in, as the README
 * tells an operator to write them. The caller matches a host as {@code URI.getHost()} gives it, so each key must
 * bind to exactly that spelling; a change in Boot's relaxed binding shows here before it shows as a mismatch.
 */
class ReceiverNamesBindingTest {

    private static Map<String, String> bound(PropertySource<?> source) {
        StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        env.getPropertySources().addFirst(source);
        return bound(env);
    }

    private static Map<String, String> bound(StandardEnvironment env) {
        ConfigurationPropertySources.attach(env);
        return Binder.get(env).bind("paztport", PaztportProperties.class).get().getReceiverNames();
    }

    @Test
    void aBracketedKeyIsTheHostWrittenInsideTheBrackets() {
        assertThat(bound(new MapPropertySource("test", Map.of(
                "paztport.receiver-names.[[::1]]", "orders",
                "paztport.receiver-names.[::2]", "payment",
                "paztport.receiver-names.[search.]", "search",
                "paztport.receiver-names.mail.", "mailer"))))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "[::1]", "orders", "::2", "payment", "search.", "search", "mail", "mailer"));
    }

    @Test
    void anEnvironmentVariableSpellsADotAsAnUnderscore() {
        assertThat(bound(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.of("PAZTPORT_RECEIVERNAMES_PAY_SVC_CLUSTER_LOCAL", "payment"))))
                .containsExactlyEntriesOf(Map.of("pay.svc.cluster.local", "payment"));
    }

    @Test
    void springApplicationJsonTakesAHyphenatedHostAndBracketsAsAFileDoes() {
        StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        env.getPropertySources().addFirst(new MapPropertySource("test", Map.of("spring.application.json",
                "{\"paztport\":{\"receiver-names\":{\"orders-internal\":\"orders\",\"[[::1]]\":\"payment\"}}}")));
        new SpringApplicationJsonEnvironmentPostProcessor().postProcessEnvironment(env, null);

        assertThat(bound(env)).containsExactlyInAnyOrderEntriesOf(Map.of(
                "orders-internal", "orders", "[::1]", "payment"));
    }
}
