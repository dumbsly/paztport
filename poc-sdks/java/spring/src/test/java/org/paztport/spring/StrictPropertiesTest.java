// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/**
 * A property under {@code paztport} that the starter does not define fails the start. Several of them guard
 * something ({@code verify}, a requirement), so a misspelling that left the default in place would fail open, and
 * Boot's default is to ignore a key it cannot bind. The context here holds only the properties bean, so what fails
 * is the binding and nothing else.
 */
class StrictPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(PaztportProperties.class)
    static class Bind {}

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Bind.class);

    private static String rootCause(Throwable t) {
        StringBuilder all = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            all.append(c.getMessage()).append('\n');
        }
        return all.toString();
    }

    @ParameterizedTest
    @ValueSource(strings = {"paztport.extensions.act-on=influence", "paztport.extension.acts-on=influence",
        "paztport.verfy=true", "paztport.overlap.keyring-path=a", "paztport.boundary.requirs=influence"})
    void aKeyTheStarterDoesNotDefineFailsTheStartNamingIt(String property) {
        String key = property.substring(0, property.indexOf('='));
        runner.withPropertyValues(property).run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootCause(context.getStartupFailure())).contains(key);
        });
    }

    @Test
    void anEnvironmentVariableThatIsNotAPropertyFailsTheStartNamingIt() {
        runner.withInitializer(context -> context.getEnvironment()
                        .getPropertySources()
                        .addFirst(new SystemEnvironmentPropertySource(
                                "systemEnvironment", Map.of("PAZTPORT_EXTENSIONS_ACT_ON", "influence"))))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootCause(context.getStartupFailure()).toLowerCase())
                            .contains("paztport.extensions.act.on")
                            .contains("act");
                });
    }

    @Test
    void aReceiverNameAndARequirementPerReceiverAreMapKeysAndStart() {
        runner.withPropertyValues(
                        "paztport.receiver-names.orders-host=orders",
                        "paztport.extensions.requires.payment=influence")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PaztportProperties p = context.getBean(PaztportProperties.class);
                    assertThat(p.getReceiverNames()).containsEntry("orders-host", "orders");
                    assertThat(p.getExtensions().getRequires().get("payment")).containsExactly("influence");
                });
    }

    /** Every row of the Java README's properties table, set together: each must bind, none may be taken as unknown. */
    @Test
    void everyPropertyTheReadmeListsBinds() {
        String[] all = Stream.of(
                        "service-name=svc", "instance=i1", "origin=false", "verify=false", "mode=audit",
                        "admin-token=t", "responder-url=https://r.example", "event-key-path=/e",
                        "event-timeout-ms=2000",
                        "key-path=/k", "keyring-path=/kr", "root-path=/r", "policy-key-path=/p", "origins=a,b",
                        "proofs-path=/pf", "max-age-ms=5000", "run-max-age-ms=5000", "unverified-paths=/health",
                        "receiver-names.orders-host=orders", "tls-bundle=false", "read-timeout-ms=30000",
                        "connect-timeout-ms=1000", "retry-unconnected=true", "overlap.keyring-paths=/a,/b",
                        "overlap.root-paths=/c", "operations.table-path=/t", "operations.receiver-tables=/x",
                        "boundary.url=https://p.example", "boundary.partner=p", "boundary.tls-bundle=b",
                        "boundary.partner-policy-key-path=/pp", "boundary.blinding-key-path=/bk",
                        "boundary.session-idle-ms=600000", "partner.enabled=false", "partner.reply-cert-path=/rc",
                        "partner.client-policy-key-paths=/c1", "partner.client-origins=o",
                        "partner.unsafe-disabled=GET /x",
                        "partner.max-sessions-per-peer=16", "partner.session-idle-ms=900000",
                        "extensions.acts-on=influence", "extensions.allowed=influence",
                        "extensions.requires.payment=influence")
                .map(p -> "paztport." + p)
                .toArray(String[]::new);
        runner.withPropertyValues(all).run(context -> assertThat(context).hasNotFailed());
    }
}
