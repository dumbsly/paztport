// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.Keyring;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Who attests, through the real container and the real RestClient. A response stamp is shaped like a request stamp,
 * so a service attests only a chain that passed the full live order there, whether or not it enforces; an origin
 * never attests; and a service with no verifier cannot know a chain is good, so it never attests either. Four apps
 * share one name, {@code localhost}, and one key, because the interceptor takes the receiver from the URI host:
 *
 * <ul>
 *   <li>{@code origin} starts request trees, as gateway does;</li>
 *   <li>{@code hop} holds a stamp key and trust material but does not verify requests, as orders and search do;</li>
 *   <li>{@code enforcingOrigin} is an origin that verifies requests;</li>
 *   <li>{@code bare} holds a stamp key and nothing to verify with.</li>
 * </ul>
 */
class AttestationRuleTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair APP = Crypto.generateEd25519KeyPair();
    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static Path trust;
    private static PolicyBuilder.Result built;
    private static String policyPub;
    private static final List<ConfigurableApplicationContext> APPS = new ArrayList<>();
    private static int origin;
    private static int hop;
    private static int enforcingOrigin;
    private static int bare;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Handlers.class)
    static class App {
    }

    @RestController
    static class Handlers {
        private final RestClient client;

        Handlers(RestClient.Builder builder) {
            this.client = builder.build();
        }

        @GetMapping("/labelled")
        String labelled() {
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
            return "alice's order history";
        }

        /** What the handler was given: the inbound chain's length (-1 for none) and the influence classes. */
        @GetMapping("/seen")
        Map<String, Object> seen() {
            List<StampV3> chain = PaztportContext.inboundChain();
            return Map.of("chain", chain == null ? -1 : chain.size(),
                    "influence", PaztportContext.influence().stream().map(e -> e.cls().wire()).toList());
        }

        /** Calls {@code path} on the app at {@code port} and reports what the call recorded as influence. */
        @GetMapping("/call")
        Map<String, Object> call(@RequestParam int port, @RequestParam String path) {
            return client.get().uri(URI.create("http://localhost:" + port + path)).exchange((request, response) -> {
                Map<String, Object> out = new HashMap<>();
                out.put("status", response.getStatusCode().value());
                out.put("attested", response.getHeaders().getFirst(PaztportHeaders.RESPONSE) != null);
                out.put("recorded", PaztportContext.influence().stream().map(e -> e.cls().wire()).toList());
                return out;
            }, false);
        }
    }

    @BeforeAll
    static void startApps() throws IOException {
        trust = Files.createTempDirectory("paztport-attestation-rule");
        KeyPair policy = Crypto.generateEd25519KeyPair();
        policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        built = PolicyBuilder.build(List.of(List.of("localhost", "localhost")), 4, policy.getPrivate());
        Files.writeString(trust.resolve("localhost.key"), Base64Url.encode(Crypto.encodePrivateKey(APP.getPrivate())));
        Files.writeString(trust.resolve("policy.pub"), policyPub);
        JSON.writeValue(trust.resolve("keyring.json").toFile(), keyring(policy));
        JSON.writeValue(trust.resolve("root.json").toFile(), built.signedRoot());
        JSON.writeValue(trust.resolve("proofs-localhost.json").toFile(), built.bundles().get("localhost"));

        origin = start(true, false, true);
        hop = start(false, false, true);
        enforcingOrigin = start(true, true, true);
        bare = start(false, false, false);
    }

    private static KeyringFile keyring(KeyPair policy) {
        return KeyringFile.sign(Map.of("localhost", Base64Url.encode(Crypto.encodePublicKey(APP.getPublic()))),
                policyPub, policy.getPrivate());
    }

    /** Starts one app on a free port and answers the port. */
    private static int start(boolean isOrigin, boolean verify, boolean withTrust) {
        List<String> props = new ArrayList<>(List.of(
                "server.port=0",
                "spring.main.banner-mode=off",
                "paztport.service-name=localhost",
                "paztport.origins=localhost",
                "paztport.origin=" + isOrigin,
                "paztport.verify=" + verify,
                "paztport.key-path=" + trust.resolve("localhost.key"),
                "paztport.proofs-path=" + trust.resolve("proofs-localhost.json")));
        if (withTrust) {
            props.add("paztport.keyring-path=" + trust.resolve("keyring.json"));
            props.add("paztport.root-path=" + trust.resolve("root.json"));
            props.add("paztport.policy-key-path=" + trust.resolve("policy.pub"));
        }
        ConfigurableApplicationContext app = new SpringApplicationBuilder(App.class)
                .properties(props.toArray(String[]::new)).run();
        APPS.add(app);
        return Integer.parseInt(app.getEnvironment().getProperty("local.server.port"));
    }

    @AfterAll
    static void stopApps() throws IOException {
        APPS.forEach(ConfigurableApplicationContext::close);
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    /** The test's own client, an origin with its own trust material and replay cache, plus {@code extra}. */
    private static RestClient caller(ClientHttpRequestInterceptor... extra) {
        VerifierV3 verifier = new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("localhost", APP.getPublic())), built.signedRoot().rootBytes(),
                built.signedRoot().rootId(), Set.of("localhost"), "", new InMemoryNonceCache(15_000),
                System::currentTimeMillis, 5000, 5000));
        RestClient.Builder b = RestClient.builder().requestInterceptor(new OutboundInterceptor(
                new StamperV3("localhost", "caller-1", APP.getPrivate(), true, () -> UUID.randomUUID().toString(),
                        System::currentTimeMillis), built.bundles().get("localhost"), verifier, "localhost"));
        for (ClientHttpRequestInterceptor i : extra) {
            b.requestInterceptor(i);
        }
        return b.build();
    }

    /** What one call answered, and what the caller recorded from it. */
    private record Answer(int status, String body, String attestation, List<InfluenceEntry> recorded) {
    }

    private static Answer get(RestClient client, int port, String path) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            return client.get().uri(URI.create("http://localhost:" + port + path)).exchange((request, response) ->
                    new Answer(response.getStatusCode().value(),
                            new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8),
                            response.getHeaders().getFirst(PaztportHeaders.RESPONSE),
                            PaztportContext.influence()), false);
        }
    }

    private static List<InfluenceClass> classes(Answer answer) {
        return answer.recorded().stream().map(InfluenceEntry::cls).toList();
    }

    @Test
    void anHonestHopThatDoesNotVerifyRequestsStillAttests() {
        Answer direct = get(caller(), hop, "/labelled");

        assertEquals("alice's order history", direct.body());
        assertNotNull(direct.attestation());
        assertEquals(List.of(InfluenceClass.PRIVATE), classes(direct), "its labels arrive verified");
        assertEquals("alice", direct.recorded().get(0).owner());
    }

    @Test
    void inTheMeshShapeTheOriginsCallToAHopComesBackVerified() throws Exception {
        // The test asks the origin to call the hop: gateway calling orders, both auto-configured.
        Answer answer = get(RestClient.create(), origin, "/call?port=" + hop + "&path=/labelled");

        Map<?, ?> reported = JSON.readValue(answer.body(), Map.class);
        assertEquals(200, reported.get("status"));
        assertEquals(true, reported.get("attested"));
        assertEquals(List.of("private"), reported.get("recorded"));
    }

    @Test
    void aForgedChainSentToAHopThatDoesNotVerifyIsServedButNeverAttested() {
        for (String sig : List.of("", Base64Url.encode(new byte[64]))) {
            // Runs after the stamping interceptor and swaps the chain for one anyone could write: an origin stamp
            // with no real signature.
            Answer answer = get(caller((request, body, execution) -> {
                StampV3 forged = new StampV3("localhost", "x", UUID.randomUUID().toString(),
                        System.currentTimeMillis(), "", "localhost", "b", Influence.commit(List.of()), "", sig);
                request.getHeaders().set(PaztportHeaders.CHAIN, HttpV3.encodeChain(List.of(forged)));
                return execution.execute(request, body);
            }), hop, "/labelled");

            assertEquals(200, answer.status(), "sig=\"" + sig + "\": not refused, since the hop does not enforce");
            assertEquals("alice's order history", answer.body());
            assertNull(answer.attestation(), "sig=\"" + sig + "\": the hop's key mints nothing");
            assertEquals(List.of(InfluenceClass.LOCAL_UNTRUSTED), classes(answer), "sig=\"" + sig + "\"");
        }
    }

    @Test
    void anOriginNeverAttestsEvenAChainThatWouldVerify() {
        for (int port : new int[] {origin, enforcingOrigin}) {
            Answer answer = get(caller(), port, "/labelled");

            assertEquals(200, answer.status(), "the chain verifies, so even the enforcing origin serves it");
            assertNull(answer.attestation());
            assertEquals(List.of(InfluenceClass.LOCAL_UNTRUSTED), classes(answer));
        }
    }

    @Test
    void anOriginStartsFromNoChainAndNoInfluence() throws Exception {
        for (int port : new int[] {origin, enforcingOrigin}) {
            Answer answer;
            try (PaztportContext.Scope scope = PaztportContext.open()) {
                // Influence the caller has read, so it is sent and committed to.
                PaztportContext.addInfluence(WEB);
                answer = caller().get().uri(URI.create("http://localhost:" + port + "/seen"))
                        .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                                new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8), null,
                                List.of()), false);
            }

            assertEquals(200, answer.status());
            assertEquals(Map.of("chain", -1, "influence", List.of()), JSON.readValue(answer.body(), Map.class));
        }
        // A hop, by contrast, carries both.
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(WEB);
            String body = caller().get().uri(URI.create("http://localhost:" + hop + "/seen")).retrieve()
                    .body(String.class);
            assertEquals(Map.of("chain", 1, "influence", List.of("third-party")), JSON.readValue(body, Map.class));
        }
    }

    @Test
    void aServiceWithAStampKeyButNoVerifierNeverAttests() {
        Answer answer = get(caller(), bare, "/labelled");

        assertEquals("alice's order history", answer.body());
        assertNull(answer.attestation());
        assertEquals(List.of(InfluenceClass.LOCAL_UNTRUSTED), classes(answer));
    }
}
