// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.OperationTable.Operation;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.ModeHolder;
import org.paztport.http.OriginIntent;
import org.paztport.http.VerificationMode;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.TestHttp;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * On the real servlet container, payment acts on {@code intent} and its handler {@code charge} requires the fact
 * {@code amount}: a request whose verified origin stated it runs the handler, which reads it; one that did not state
 * it, or that was served without verifying (audit mode after a failed chain, mode off), is refused
 * {@code 403 INTENT_MISSING} before the handler runs; a handler that requires nothing is served as before. The
 * refusal is never attested, with an operation table or without one, while the handler's own answer on the same
 * service is. The dispatch check answers before the intent check, and a service whose handlers are annotated but that
 * does not act on intent, or that names no fact or a bad one, does not start.
 */
class IntentCheckTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final HttpClient http = TestHttp.newClient();

    /** The handlers that ran, by name, in order. */
    private static final List<String> RAN = new CopyOnWriteArrayList<>();

    /** The amount {@code charge} read from the facts. */
    private static final AtomicReference<Long> SEEN = new AtomicReference<>();

    /** Payment's table: each of its handlers is an operation. */
    private static final OperationTable PAYMENT = new OperationTable("payment", List.of(
            new Operation("charge", "POST", "/charge"),
            new Operation("plain", "POST", "/plain"),
            new Operation("later", "POST", "/later")));

    private static final IntentFacts AMOUNT = IntentFacts.builder().put("amount", 100).put("order", "123").build();
    private static final IntentFacts NO_AMOUNT = IntentFacts.builder().put("order", "123").build();

    /** A property that gives payment its own table, so that its chains may name its operations. */
    private static final String WITH_TABLE = "with-table";

    @BeforeEach
    void forget() {
        RAN.clear();
        SEEN.set(null);
    }

    @AfterAll
    static void closeClient() {
        http.close();
    }

    @Test
    void anAnnotatedHandlerRunsWithItsFacts(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce")) {
            HttpResponse<String> answer = payment.send("/charge", "payment", AMOUNT);

            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("charged");
            assertThat(RAN).containsExactly("charge");
            assertThat(SEEN.get()).isEqualTo(100L);
        }
    }

    /**
     * A handler that answers from async work is checked on the request's own dispatch, not again as it resumes. A
     * handler that passed and then async-dispatches the request to another annotated handler does not let that one
     * through: it is checked, outside the request's scope, so it is refused and does not run.
     */
    @Test
    void anAsyncHandlerIsCheckedOnTheRequestsOwnDispatch(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce")) {
            HttpResponse<String> served = payment.send("/later", "payment", AMOUNT);
            assertThat(served.statusCode()).isEqualTo(200);
            assertThat(served.body()).isEqualTo("later");

            HttpResponse<String> refused = payment.send("/later", "payment", NO_AMOUNT);
            assertThat(refused.statusCode()).isEqualTo(403);
            assertThat(refused.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
            assertThat(RAN).containsExactly("later");

            RAN.clear();
            HttpResponse<String> other = payment.send("/hop", "payment", AMOUNT);
            assertThat(other.statusCode()).isEqualTo(403);
            assertThat(other.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
            assertThat(RAN).as("hop passed and ran; the handler it dispatched to did not").containsExactly("hop");
        }
    }

    @Test
    void aMissingFactIsRefusedBeforeTheHandler(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce")) {
            for (IntentFacts facts : Arrays.asList(NO_AMOUNT, null)) {
                HttpResponse<String> answer = payment.send("/charge", "payment", facts);

                assertThat(answer.statusCode()).as(String.valueOf(facts)).isEqualTo(403);
                assertThat(answer.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
                assertThat(answer.headers().firstValue("Content-Type")).hasValue("application/json");
            }
            assertThat(RAN).as("the handler never ran").isEmpty();
        }
    }

    @Test
    void anUnverifiedRequestIsRefusedInAuditMode(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "audit")) {
            HttpResponse<String> answer = payment.sendTampered("/charge", "payment", AMOUNT);

            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
            assertThat(RAN).as("not served, though audit serves the chain that failed").isEmpty();
        }
    }

    @Test
    void aServiceWithPaztportOffRefusesAnAnnotatedHandler(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "off")) {
            HttpResponse<String> answer = payment.send("/charge", "payment", AMOUNT);

            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
            assertThat(RAN).isEmpty();
        }
    }

    @Test
    void aHandlerWithoutTheAnnotationIsUntouched(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce")) {
            assertThat(payment.send("/plain", "payment", NO_AMOUNT).statusCode()).isEqualTo(200);
            assertThat(payment.send("/plain", "payment", null).statusCode()).isEqualTo(200);

            payment.mode(VerificationMode.AUDIT);
            assertThat(payment.sendTampered("/plain", "payment", AMOUNT).statusCode()).isEqualTo(200);

            payment.mode(VerificationMode.OFF);
            HttpResponse<String> off = payment.send("/plain", "payment", AMOUNT);
            assertThat(off.statusCode()).isEqualTo(200);
            assertThat(off.body()).isEqualTo("plain");
            assertThat(RAN).containsExactly("plain", "plain", "plain", "plain");
        }
    }

    /**
     * Without a table nothing but the refusal's own mark keeps it unattested; with one, the handler was never reached
     * as well. A chain that names no operation records none, even with a table, so it is checked there too. The
     * handler's own answer on the same service is attested each time, so attestation is on.
     */
    @Test
    void theRefusalIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir.resolve("plain"), App.class, "enforce")) {
            assertUnattestedRefusal(payment, "payment");
        }
        try (Service payment = Service.start(dir.resolve("table"), App.class, "enforce", WITH_TABLE)) {
            assertUnattestedRefusal(payment, "payment#");
            assertUnattestedRefusal(payment, "payment");
        }
    }

    /** {@code named} is the receiver gateway names: the bare service, or with {@code #} each handler's operation. */
    private static void assertUnattestedRefusal(Service payment, String named) throws Exception {
        boolean operation = named.endsWith("#");
        HttpResponse<String> refused = payment.send("/charge", operation ? named + "charge" : named, NO_AMOUNT);
        assertThat(refused.statusCode()).isEqualTo(403);
        assertThat(refused.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
        assertThat(attestation(refused)).as(named + ": the refusal is not attested").isNull();

        HttpResponse<String> served = payment.send("/plain", operation ? named + "plain" : named, NO_AMOUNT);
        assertThat(served.statusCode()).isEqualTo(200);
        assertThat(attestation(served)).as(named + ": the handler's own answer is attested").isNotNull();
        HttpResponse<String> charged = payment.send("/charge", operation ? named + "charge" : named, AMOUNT);
        assertThat(charged.statusCode()).isEqualTo(200);
        assertThat(attestation(charged)).as(named + ": as is the annotated handler's").isNotNull();
    }

    /**
     * A filter after Paztport's turns a request verified for {@code plain} into one for {@code charge}, which
     * requires a fact the request does not carry: the dispatch check refuses it first, so the answer is
     * {@code BINDING_MISMATCH}, not {@code INTENT_MISSING}. The intent check's bean is registered after the dispatch
     * check's, and this test is what holds that order.
     */
    @Test
    void theDispatchCheckAnswersFirst(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce", WITH_TABLE)) {
            HttpResponse<String> answer = payment.send("/plain", "payment#plain", null, "charge");

            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).isEmpty();
        }
    }

    /**
     * A filter after Paztport's includes {@code charge} in place of the request's own dispatch. An included handler
     * cannot set the status, so the inbound filter writes the refusal once the chain returns, as it does the dispatch
     * check's, and the handler does not run; with the fact stated, it runs.
     */
    @Test
    void anIncludedHandlerIsRefusedAsTheDispatchCheckRefusesOne(@TempDir Path dir) throws Exception {
        try (Service payment = Service.start(dir, App.class, "enforce")) {
            HttpResponse<String> refused = payment.send("/plain", "payment", NO_AMOUNT, "include:charge");
            assertThat(refused.statusCode()).isEqualTo(403);
            assertThat(refused.body()).isEqualTo("{\"reason\":\"INTENT_MISSING\"}");
            assertThat(refused.headers().firstValue("Content-Type")).hasValue("application/json");
            assertThat(attestation(refused)).isNull();
            assertThat(RAN).isEmpty();

            HttpResponse<String> served = payment.send("/plain", "payment", AMOUNT, "include:charge");
            assertThat(served.body()).isEqualTo("charged");
            assertThat(RAN).containsExactly("charge");
        }
    }

    /** An annotation on a bean's method that no request mapping maps would be checked by nothing. */
    @Test
    void startupFailsOnAMisplacedAnnotation(@TempDir Path dir) throws Exception {
        Throwable failed = catchThrowable(() -> Service.start(dir, MisplacedApp.class, "enforce").close());

        assertThat(messages(failed)).anySatisfy(message -> assertThat(message)
                .contains(Pricing.class.getName() + "#price").contains("not a request-mapping handler method"));
    }

    @Test
    void startupFailsWhenTheServiceDoesNotActOnIntent(@TempDir Path dir) throws Exception {
        List<String> settings = List.of("paztport.extensions.acts-on=influence", "unset");
        for (int i = 0; i < settings.size(); i++) {
            String actsOn = settings.get(i);
            Path files = dir.resolve("service-" + i);
            Throwable failed = catchThrowable(() -> Service.start(files, App.class, "enforce", actsOn).close());

            assertThat(messages(failed)).as(actsOn).anySatisfy(message -> assertThat(message)
                    .contains(Handlers.class.getName() + "#charge").contains("paztport.extensions.acts-on")
                    .contains("intent"));
        }
    }

    @Test
    void startupFailsOnAnEmptyOrBadName(@TempDir Path dir) throws Exception {
        Throwable empty = catchThrowable(() -> Service.start(dir.resolve("empty"), EmptyApp.class, "enforce")
                .close());
        assertThat(messages(empty)).anySatisfy(message -> assertThat(message)
                .contains(EmptyHandlers.class.getName() + "#none").contains("names no fact"));

        Throwable bad = catchThrowable(() -> Service.start(dir.resolve("bad"), BadApp.class, "enforce").close());
        assertThat(messages(bad)).anySatisfy(message -> assertThat(message)
                .contains(BadHandlers.class.getName() + "#capital").contains("not a fact name"));
    }

    /** The messages of {@code thrown} and each of its causes, in order. */
    private static List<String> messages(Throwable thrown) {
        assertThat(thrown).as("the context did not start").isNotNull();
        List<String> messages = new ArrayList<>();
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            messages.add(String.valueOf(t.getMessage()));
        }
        return messages;
    }

    private static String attestation(HttpResponse<String> answer) {
        return answer.headers().firstValue(PaztportHeaders.RESPONSE).orElse(null);
    }

    /**
     * Payment, run as {@code app} on a free port, acting on intent unless told otherwise, holding its stamp key so
     * that it attests, and gateway's keys and proofs to call it with. Gateway may call payment by its name alone and
     * each of its operations.
     */
    private record Service(ConfigurableApplicationContext app, KeyPair gateway, PolicyBuilder.Result built, int port)
            implements AutoCloseable {

        static Service start(Path dir, Class<?> app, String mode, String... more) throws IOException {
            Files.createDirectories(dir);
            KeyPair policy = Crypto.generateEd25519KeyPair();
            KeyPair gateway = Crypto.generateEd25519KeyPair();
            KeyPair payment = Crypto.generateEd25519KeyPair();
            String pin = pub(policy);
            PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "payment"),
                    List.of("gateway", "payment#charge"), List.of("gateway", "payment#plain"),
                    List.of("gateway", "payment#later"), PAYMENT.route()), 4, NOT_AFTER, policy.getPrivate());
            Files.writeString(dir.resolve("policy.pub"), pin + "\n");
            Files.writeString(dir.resolve("payment.key"),
                    Base64Url.encode(Crypto.encodePrivateKey(payment.getPrivate())));
            Files.writeString(dir.resolve("keyring.json"), KeyringFile.sign(
                    Map.of("gateway", pub(gateway), "payment", pub(payment)), pin, NOT_AFTER,
                    policy.getPrivate()).toFile());
            Files.writeString(dir.resolve("root.json"), built.signedRoot().toFile());
            Files.writeString(dir.resolve("proofs-payment.json"), built.bundles().get("payment").toFile());
            Files.writeString(dir.resolve("ops-payment.json"), PAYMENT.toFile());

            List<String> props = new ArrayList<>(List.of("server.port=0", "spring.main.banner-mode=off",
                    "paztport.service-name=payment", "paztport.origins=gateway", "paztport.verify=true",
                    "paztport.mode=" + mode,
                    "paztport.key-path=" + dir.resolve("payment.key"),
                    "paztport.proofs-path=" + dir.resolve("proofs-payment.json"),
                    "paztport.keyring-path=" + dir.resolve("keyring.json"),
                    "paztport.root-path=" + dir.resolve("root.json"),
                    "paztport.policy-key-path=" + dir.resolve("policy.pub")));
            List<String> extra = new ArrayList<>(List.of(more));
            if (extra.remove(WITH_TABLE)) {
                props.add("paztport.operations.table-path=" + dir.resolve("ops-payment.json"));
            }
            boolean actsOnSet = extra.stream().anyMatch(p -> p.startsWith("paztport.extensions.acts-on="));
            if (!extra.remove("unset") && !actsOnSet) {
                props.add("paztport.extensions.acts-on=" + Intent.NAME);
            }
            props.addAll(extra);
            ConfigurableApplicationContext context = new SpringApplicationBuilder(app)
                    .properties(props.toArray(String[]::new)).run();
            return new Service(context, gateway, built,
                    Integer.parseInt(context.getEnvironment().getProperty("local.server.port")));
        }

        private static String pub(KeyPair k) {
            return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
        }

        /** Switches payment's mode, as an operator would at runtime. */
        void mode(VerificationMode mode) {
            app.getBean(ModeHolder.class).set(mode);
        }

        /** {@code POST target} from gateway, naming {@code rcv}, its block holding {@code facts} where not null. */
        HttpResponse<String> send(String target, String rcv, IntentFacts facts) throws Exception {
            return send(target, rcv, facts, null);
        }

        /** As {@link #send}, asking the test's filter to turn the request into one for {@code rewrite}. */
        HttpResponse<String> send(String target, String rcv, IntentFacts facts, String rewrite) throws Exception {
            return exchange(target, rcv, facts, rewrite, "{}");
        }

        /** As {@link #send}, with a body other than the one gateway's stamp binds, so the chain fails here. */
        HttpResponse<String> sendTampered(String target, String rcv, IntentFacts facts) throws Exception {
            return exchange(target, rcv, facts, null, "{\"amount\":999}");
        }

        private HttpResponse<String> exchange(String target, String rcv, IntentFacts facts, String rewrite,
                String body) throws Exception {
            String rid = UUID.randomUUID().toString();
            Block block = facts == null ? Block.EMPTY : Block.of(Map.of(Intent.NAME, List.of(facts.toItem())),
                    List.of());
            Stamper.Stamped sent = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid,
                    System::currentTimeMillis).next(null, rcv, RequestBinding.compute("POST", target,
                    "{}".getBytes(StandardCharsets.UTF_8)), block, built.bundles().get("gateway"));
            HttpRequest.Builder request = TestHttp.request(URI.create("http://127.0.0.1:" + port + target))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .header("Content-Type", "application/json")
                    .header(PaztportHeaders.CHAIN, HttpWire.encodeChain(sent.chain()))
                    .header(PaztportHeaders.EXTENSIONS, HttpWire.encodeBlocks(List.of(block)));
            if (sent.proof() != null) {
                request.header(PaztportHeaders.PROOF, HttpWire.encodeProof(sent.proof()));
            }
            if (rewrite != null) {
                request.header(Rewrite.HEADER, rewrite);
            }
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        }

        @Override
        public void close() {
            app.close();
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Handlers.class)
    static class App {

        /** Registered as an application registers a filter, so it runs after Paztport's. */
        @Bean
        FilterRegistrationBean<Rewrite> rewrite() {
            return new FilterRegistrationBean<>(new Rewrite());
        }
    }

    /**
     * Turns the request into one for the path the test's header names, or for {@code include:<path>} includes that
     * path in place of the request's own dispatch, as a filter after Paztport's might.
     */
    static final class Rewrite extends OncePerRequestFilter {

        static final String HEADER = "X-Test-Rewrite";

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String rewrite = request.getHeader(HEADER);
            if (rewrite == null) {
                chain.doFilter(request, response);
                return;
            }
            if (rewrite.startsWith("include:")) {
                request.getRequestDispatcher("/" + rewrite.substring("include:".length())).include(request, response);
                return;
            }
            String path = "/" + rewrite;
            chain.doFilter(new HttpServletRequestWrapper(request) {
                @Override
                public String getRequestURI() {
                    return path;
                }

                @Override
                public StringBuffer getRequestURL() {
                    return new StringBuffer("http://127.0.0.1" + path);
                }

                @Override
                public String getServletPath() {
                    return path;
                }
            }, response);
        }
    }

    /** Payment's handlers: {@code charge} and {@code later} require {@code amount}, {@code plain} requires none. */
    @RestController
    static class Handlers {

        private final OriginIntent intent;

        Handlers(OriginIntent intent) {
            this.intent = intent;
        }

        @PostMapping("/charge")
        @RequiresIntent("amount")
        String charge() {
            RAN.add("charge");
            SEEN.set(intent.facts().integer("amount"));
            return "charged";
        }

        @PostMapping("/plain")
        String plain() {
            RAN.add("plain");
            return "plain";
        }

        @PostMapping("/later")
        @RequiresIntent("amount")
        Callable<String> later() {
            RAN.add("later");
            return () -> "later";
        }

        /** Passes on {@code amount}, then dispatches the request's async work to {@code other}. */
        @PostMapping("/hop")
        @RequiresIntent("amount")
        void hop(HttpServletRequest request) {
            RAN.add("hop");
            request.startAsync().dispatch("/other");
        }

        /** Requires a fact {@code hop} does not, so it must be checked on its own. */
        @PostMapping("/other")
        @RequiresIntent("customer")
        String other() {
            RAN.add("other");
            return "other";
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(EmptyHandlers.class)
    static class EmptyApp {
    }

    /** A handler that requires no fact by name, which is a mistake rather than a requirement. */
    @RestController
    static class EmptyHandlers {

        @PostMapping("/none")
        @RequiresIntent({})
        String none() {
            return "none";
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(BadHandlers.class)
    static class BadApp {
    }

    /** A handler that requires a name no fact can have. */
    @RestController
    static class BadHandlers {

        @PostMapping("/capital")
        @RequiresIntent("Amount")
        String capital() {
            return "capital";
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({Handlers.class, Pricing.class})
    static class MisplacedApp {
    }

    /** A helper bean whose method carries the annotation, though no request mapping maps it. */
    static class Pricing {

        @RequiresIntent("amount")
        long price(long amount) {
            return amount;
        }
    }
}
