// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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

    private static String causeMessages(Throwable t) {
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
            assertThat(causeMessages(context.getStartupFailure())).contains(key);
        });
    }

    /** The environment as a process has it: a source named {@code systemEnvironment}, since a test cannot set one. */
    private ApplicationContextRunner withEnvironment(Map<String, Object> variables) {
        // The trust material that overlap.* and operations.* need beside them is given as property values, so that a
        // variable for one of those is tested for its binding and not for the existing check that its neighbours are
        // set; a property value is not in the environment source, so it never stands in for the variable under test.
        return runner.withPropertyValues("paztport.keyring-path=/kr", "paztport.root-path=/r",
                        "paztport.policy-key-path=/p", "paztport.proofs-path=/pf")
                .withInitializer(context -> context.getEnvironment()
                .getPropertySources()
                .addFirst(new SystemEnvironmentPropertySource("systemEnvironment", variables)));
    }

    /**
     * Variables from name-and-value pairs.
     */
    private static Map<String, Object> variables(String... nameValuePairs) {
        Map<String, Object> all = new HashMap<>();
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            all.put(nameValuePairs[i], nameValuePairs[i + 1]);
        }
        return all;
    }

    private void assertStarts(Map<String, Object> variables) {
        withEnvironment(variables).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(PaztportProperties.class)).isNotNull();
        });
    }

    private void assertRefuses(String variable, String value) {
        withEnvironment(variables(variable, value)).run(context -> {
            assertThat(context).hasFailed();
            assertThat(causeMessages(context.getStartupFailure())).contains(variable);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"PAZTPORT_EXTENSIONS_ACT_ON", "PAZTPORT_VERFY", "PAZTPORT_RUN_MAX_AGE", "PAZTPORT_CAPTURE",
        // Boot binds a map's entries only under the dash-less parent, so this one it would drop without a word.
        "PAZTPORT_RECEIVER_NAMES_ORDERSHOST"})
    void anEnvironmentVariableThatIsNotAPropertyFailsTheStartNamingIt(String variable) {
        assertRefuses(variable, "influence");
    }

    @Test
    void anUnrelatedVariableIsLeftAlone() {
        assertStarts(variables("HOME", "/home/x", "PAZTPORTAL_X", "1", "OTHER_THING", "y"));
    }

    /**
     * The Java README's properties table, less the {@code receiver-names} map (its own tests), then the extension
     * properties that the table lacks.
     */
    private static final List<String> PROPERTIES = List.of(
            "service-name=svc", "instance=i1", "origin=false", "verify=false", "mode=audit", "admin-token=t",
            "responder-url=https://r.example", "event-key-path=/e", "event-timeout-ms=2000", "key-path=/k",
            "keyring-path=/kr", "root-path=/r", "policy-key-path=/p", "origins=a,b", "proofs-path=/pf",
            "max-age-ms=5000", "run-max-age-ms=5000", "unverified-paths=/health", "tls-bundle=false",
            "read-timeout-ms=30000", "connect-timeout-ms=1000", "retry-unconnected=true",
            "overlap.keyring-paths=/a,/b", "overlap.root-paths=/c", "operations.table-path=/t",
            "operations.receiver-tables=/x", "boundary.url=https://p.example", "boundary.partner=p",
            "boundary.tls-bundle=b", "boundary.partner-policy-key-path=/pp", "boundary.blinding-key-path=/bk",
            "boundary.session-idle-ms=600000", "partner.enabled=false", "partner.reply-cert-path=/rc",
            "partner.client-policy-key-paths=/c1", "partner.client-origins=o", "partner.unsafe-disabled=GET /x",
            "partner.max-sessions-per-peer=16", "partner.session-idle-ms=900000", "extensions.acts-on=influence",
            "extensions.allowed=influence", "boundary.requires=influence",
            "boundary.continue-without-required=true");

    /** One README property as an environment variable: a dash becomes an underscore, or is dropped (both bind). */
    static Stream<Arguments> environmentForms() {
        return PROPERTIES.stream().flatMap(entry -> {
            String name = entry.substring(0, entry.indexOf('='));
            String value = entry.substring(entry.indexOf('=') + 1);
            String root = "PAZTPORT_" + name.replace('.', '_').toUpperCase(Locale.ROOT);
            return Stream.of(
                    Arguments.of(root.replace('-', '_'), value), Arguments.of(root.replace("-", ""), value));
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("environmentForms")
    void everyPropertyTheReadmeListsStartsWrittenAsAnEnvironmentVariable(String variable, String value) {
        assertStarts(variables(variable, value));
    }

    @Test
    void listIndexAndMapKeyVariablesStart() {
        assertStarts(variables(
                "PAZTPORT_ORIGINS_0", "edge", "PAZTPORT_ORIGINS_1", "b",
                "PAZTPORT_RECEIVERNAMES_ORDERSHOST", "orders", "PAZTPORT_RECEIVERNAMES_PAY_SVC", "payment",
                "PAZTPORT_EXTENSIONS_REQUIRES_PAYMENT", "influence", "PAZTPORT_EXTENSIONS_ACTS_ON_0", "influence"));
    }

    /** The names the mesh's docker-compose.yml and the Envoy Gateway manifests pass to a Spring service. */
    @ParameterizedTest
    @ValueSource(strings = {"PAZTPORT_ADMIN_TOKEN=t", "PAZTPORT_BOUNDARY_BLINDING_KEY_PATH=/b",
        "PAZTPORT_BOUNDARY_PARTNER=p", "PAZTPORT_BOUNDARY_PARTNER_POLICY_KEY_PATH=/p",
        "PAZTPORT_BOUNDARY_TLS_BUNDLE=b", "PAZTPORT_BOUNDARY_URL=https://p.example", "PAZTPORT_EVENT_KEY_PATH=/e",
        "PAZTPORT_KEYRING_PATH=/kr", "PAZTPORT_KEY_PATH=/k", "PAZTPORT_MODE=audit", "PAZTPORT_MAX_AGE_MS=5000",
        "PAZTPORT_OPERATIONS_RECEIVERTABLES=/x", "PAZTPORT_OPERATIONS_TABLEPATH=/t", "PAZTPORT_ORIGINS=edge",
        "PAZTPORT_OVERLAP_KEYRINGPATHS=/a", "PAZTPORT_OVERLAP_ROOTPATHS=/c",
        "PAZTPORT_PARTNER_CLIENT_POLICY_KEY_PATHS=/c1", "PAZTPORT_PARTNER_REPLY_CERT_PATH=/rc",
        "PAZTPORT_POLICY_KEY_PATH=/p", "PAZTPORT_PROOFS_PATH=/pf", "PAZTPORT_ROOT_PATH=/r",
        "PAZTPORT_RUN_MAX_AGE_MS=5000", "PAZTPORT_UNVERIFIED_PATHS=/health", "PAZTPORT_VERIFY=false"})
    void aVariableTheDemosPassStarts(String pair) {
        assertStarts(variables(pair.substring(0, pair.indexOf('=')), pair.substring(pair.indexOf('=') + 1)));
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

    /** Every property in {@link #PROPERTIES}, set together as property values: each must bind. */
    @Test
    void everyPropertyBindsAsAPropertyValue() {
        runner.withPropertyValues(PROPERTIES.stream().map(p -> "paztport." + p).toArray(String[]::new))
                .run(context -> assertThat(context).hasNotFailed());
    }
}
