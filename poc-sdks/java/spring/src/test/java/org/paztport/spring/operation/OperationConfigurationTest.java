// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.anything;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.ContextAccess;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.InboundFilter;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.TestHttp;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;

/**
 * A table is used only where the signed root covers it, which the service's own bundle shows against the pinned
 * roots: the service's own table must be, or it does not start; a receiver's table its bundle holds no proof for is
 * set aside, so calls to that receiver name no operation; and a proof that is there but does not verify stops the
 * start. Then, end to end, the filter confirms the operation the request is dispatched to.
 */
class OperationConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class, PaztportAutoConfiguration.class))
            .withUserConfiguration(Handlers.class);

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger log = (Logger) LoggerFactory.getLogger(OperationConfiguration.class);

    @BeforeEach
    void captureLog() {
        logged.start();
        log.addAppender(logged);
        log.setLevel(Level.INFO);
    }

    @AfterEach
    void cleanup() {
        log.detachAppender(logged);
        log.setLevel(null);
        ContextAccess.reset();
    }

    @Test
    void startFailsWhenTheOwnTableIsNotCovered(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routesWithout(OperationWorld.ORDERS.route()));
        runner.withPropertyValues(world.service("orders",
                        "paztport.operations.table-path=" + world.file("ops-orders.json")))
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("paztport.operations.table-path")
                        .hasMessageContaining(String.join("/", OperationWorld.ORDERS.route())));
    }

    @Test
    void startFailsWhenTheOwnTableIsAnotherServicesTable(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runner.withPropertyValues(world.service("orders",
                        "paztport.operations.table-path=" + world.file("ops-payment.json")))
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("paztport.operations.table-path").hasMessageContaining("payment"));
    }

    @Test
    void startFailsBesideTheMethodOverrideFilter(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        // The filter rewrites the method after the inbound filter confirmed the operation for the one sent.
        runner.withPropertyValues(world.service("orders",
                        "paztport.operations.table-path=" + world.file("ops-orders.json"),
                        "spring.mvc.hiddenmethod.filter.enabled=true"))
                .run(context -> assertThat(context).getFailure()
                        .hasMessageContaining("paztport.operations.table-path")
                        .hasMessageContaining("HiddenHttpMethodFilter"));
    }

    @Test
    void aTableNeedsTheProofsAndThePinnedTrust(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runner.withPropertyValues("paztport.service-name=gateway", "paztport.origin=true",
                        "paztport.key-path=" + world.file("gateway.key"),
                        "paztport.operations.receiver-tables=" + world.file("ops-orders.json"))
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("paztport.operations.receiver-tables")
                        .hasMessageContaining("paztport.proofs-path"));
    }

    @Test
    void receiverTableWithoutAProofIsIgnored(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        assertThat(rcvOfACallToOrders(world)).isEqualTo("orders#getOrder");
        assertThat(logged.list).isEmpty();

        world.write(OperationWorld.routesWithout(OperationWorld.ORDERS.route()));
        assertThat(rcvOfACallToOrders(world)).as("named bare: orders then needs a route that names no operation")
                .isEqualTo("orders");
        assertThat(logged.list).hasSize(1);
        assertThat(logged.list.get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logged.list.get(0).getFormattedMessage()).contains("orders");
    }

    /** The {@code rcv} gateway stamps on a call to orders' {@code GET /orders/123}, holding orders' table. */
    private String rcvOfACallToOrders(OperationWorld world) {
        List<String> rcvs = new ArrayList<>();
        runner.withPropertyValues(world.service("gateway", "paztport.origin=true",
                        "paztport.operations.receiver-tables=" + world.file("ops-orders.json")))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    RestClient.Builder builder = RestClient.builder();
                    context.getBean("paztportRestClientCustomizer", RestClientCustomizer.class).customize(builder);
                    MockRestServiceServer.bindTo(builder).build().expect(times(1), anything())
                            .andRespond(request -> {
                                List<Stamp> chain = Chains.parse(HttpWire.decodeChain(
                                        request.getHeaders().getFirst(PaztportHeaders.CHAIN))).stamps();
                                rcvs.add(chain.get(chain.size() - 1).rcv());
                                return withSuccess().createResponse(request);
                            });
                    builder.build().get().uri("http://orders/orders/123").retrieve().toBodilessEntity();
                });
        assertThat(rcvs).hasSize(1);
        return rcvs.get(0);
    }

    @Test
    void receiverTableWithABadProofFailsTheStart(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        // Present for orders' table route, but the proof of another route, so it proves nothing about the table.
        world.writeBundle(OperationWorld.swapped(built.bundles().get("gateway"), OperationWorld.ORDERS,
                List.of("gateway", "orders#getOrder")));
        runner.withPropertyValues(world.service("gateway", "paztport.origin=true",
                        "paztport.operations.receiver-tables=" + world.file("ops-orders.json")))
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("paztport.operations.receiver-tables")
                        .hasMessageContaining("does not verify"));
    }

    // --- End to end, through the filter ---

    /** Runs orders, verifying gateway's requests and holding its own table, with the filter in front of MockMvc. */
    private void runOrders(OperationWorld world, MvcConsumer then) {
        runService(runner, world, "orders", then);
    }

    /** Runs payment, as {@link #runOrders} runs orders, with the handlers of {@code POST /charge} and {@code pay}. */
    private void runPayment(OperationWorld world, MvcConsumer then) {
        runService(new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class,
                        PaztportAutoConfiguration.class))
                .withUserConfiguration(PaymentHandlers.Charges.class, PaymentHandlers.PayJson.class),
                world, "payment", then);
    }

    private static void runService(WebApplicationContextRunner runner, OperationWorld world, String service,
            MvcConsumer then) {
        runner.withPropertyValues(world.service(service, "paztport.verify=true", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-" + service + ".json")))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    InboundFilter filter = context.getBean("paztportInboundFilterRegistration",
                            FilterRegistrationBean.class).getFilter() instanceof InboundFilter f ? f : null;
                    then.accept(MockMvcBuilders.webAppContextSetup(context).addFilters(filter).build(), context);
                });
    }

    private interface MvcConsumer {
        void accept(MockMvc mvc, AssertableWebApplicationContext context) throws Exception;
    }

    /** Gateway's first hop of {@code GET uri}, naming {@code rcv}, as its chain and proof headers. */
    private static String[] firstHop(OperationWorld world, PolicyBuilder.Result built, String rcv, String uri,
            String rid) {
        return firstHop(world, built, rcv, "GET", uri, new byte[0], rid);
    }

    /** Gateway's first hop of {@code method uri} with {@code body}, naming {@code rcv}. */
    private static String[] firstHop(OperationWorld world, PolicyBuilder.Result built, String rcv, String method,
            String uri, byte[] body, String rid) {
        Stamper.Stamped sent = new Stamper("gateway", "gw-1", world.gateway.getPrivate(), true, () -> rid,
                System::currentTimeMillis).next(null, rcv, RequestBinding.compute(method, uri, body), List.of(),
                built.bundles().get("gateway"));
        return new String[] {HttpWire.encodeChain(sent.chain()),
            sent.proof() == null ? null : HttpWire.encodeProof(sent.proof()), HttpWire.encodeInfluence(List.of())};
    }

    private static ResultActions send(MockMvc mvc, String uri, String[] hop) throws Exception {
        return send(mvc, get(URI.create(uri)), hop);
    }

    /** {@code POST uri} with {@code hop}, and with {@code body} as {@code contentType} where it is not null. */
    private static ResultActions post(MockMvc mvc, String uri, String contentType, byte[] body, String[] hop)
            throws Exception {
        MockHttpServletRequestBuilder request = MockMvcRequestBuilders.post(URI.create(uri));
        if (contentType != null) {
            request.contentType(contentType).content(body);
        }
        return send(mvc, request, hop);
    }

    private static ResultActions send(MockMvc mvc, MockHttpServletRequestBuilder request, String[] hop)
            throws Exception {
        // A URI, not a template, so that a percent-encoded path or query is sent as it stands.
        request.header(PaztportHeaders.CHAIN, hop[0]);
        if (hop[1] != null) {
            request.header(PaztportHeaders.PROOF, hop[1]);
        }
        if (hop[2] != null) {
            request.header(PaztportHeaders.INFLUENCE, hop[2]);
        }
        return mvc.perform(request);
    }

    @Test
    void filterRefusesAChainNamingAnotherOperation(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        runOrders(world, (mvc, context) -> {
            send(mvc, "/orders/123", firstHop(world, built, "orders#createOrder", "/orders/123", "rid-1"))
                    .andExpect(status().isForbidden())
                    .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
            send(mvc, "/orders/123", firstHop(world, built, "orders#getOrder", "/orders/123", "rid-2"))
                    .andExpect(status().isOk()).andExpect(content().string("getOrder"));
        });
    }

    /**
     * A path the caller's table and Spring match differently is refused before any handler, never served by
     * another one: the caller names the operation its table matches, and the request goes elsewhere or nowhere.
     */
    @Test
    void aPathSpringMatchesOtherwiseIsRefused(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        runOrders(world, (mvc, context) -> {
            int rid = 0;
            for (String[] call : List.of(
                    new String[] {"/orders/", "orders#getOrder"},
                    new String[] {"/items/abc", "orders#getItem"},
                    new String[] {"/orders/%73earch", "orders#getOrder"})) {
                send(mvc, call[0], firstHop(world, built, call[1], call[0], "rid-" + rid++))
                        .andExpect(status().isForbidden())
                        .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
            }
            send(mvc, "/items/42", firstHop(world, built, "orders#getItem", "/items/42", "rid-" + rid))
                    .andExpect(status().isOk()).andExpect(content().string("getItem"));
        });
    }

    /**
     * Of an entrance's operations, the one confirmed is the handler Spring runs, which its query condition picks: a
     * chain naming the other is refused before any handler runs.
     */
    @Test
    void chainNamingChargeOnARefundRequestIsRefused(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        runPayment(world, (mvc, context) -> {
            String uri = "/charge?mode=refund";
            post(mvc, uri, null, null, firstHop(world, built, "payment#charge", "POST", uri, new byte[0], "rid-1"))
                    .andExpect(status().isForbidden())
                    .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
            assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
            post(mvc, uri, null, null, firstHop(world, built, "payment#refund", "POST", uri, new byte[0], "rid-2"))
                    .andExpect(status().isOk()).andExpect(content().string("refund"));
            assertThat(PaymentHandlers.RAN).containsExactly("refund");
        });
    }

    /**
     * Two beans that inherit one handler method, told apart by a class-level {@code params} condition, are each
     * their own operation: a chain naming either on the other's request is refused before any handler runs, and one
     * naming the operation the request has runs that bean.
     */
    @Test
    void inheritedHandlersAreEachTheirOwnOperation(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        runService(new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class,
                        PaztportAutoConfiguration.class))
                .withUserConfiguration(PaymentHandlers.ChargeSide.class, PaymentHandlers.RefundSide.class,
                        PaymentHandlers.PayJson.class),
                world, "payment", (mvc, context) -> {
                    int rid = 0;
                    for (String[] wrong : List.of(new String[] {"/charge", "payment#refund"},
                            new String[] {"/charge?mode=refund", "payment#charge"})) {
                        post(mvc, wrong[0], null, null, firstHop(world, built, wrong[1], "POST", wrong[0],
                                new byte[0], "rid-" + rid++))
                                .andExpect(status().isForbidden())
                                .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
                    }
                    assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
                    for (String[] right : List.of(new String[] {"/charge", "payment#charge", "charge side"},
                            new String[] {"/charge?mode=refund", "payment#refund", "refund side"})) {
                        post(mvc, right[0], null, null, firstHop(world, built, right[1], "POST", right[0],
                                new byte[0], "rid-" + rid++))
                                .andExpect(status().isOk()).andExpect(content().string(right[2]));
                    }
                    assertThat(PaymentHandlers.RAN).containsExactly("charge side", "refund side");
                });
    }

    /**
     * A caller matches the raw query, which holds no {@code mode=refund}, so it names {@code charge}; Spring reads the
     * decoded parameter and runs {@code refund}, so the chain is refused.
     */
    @Test
    void encodedConditionIsRefused(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        runPayment(world, (mvc, context) -> {
            String uri = "/charge?mode=%72efund";
            assertThat(OperationWorld.PAYMENT.match("POST", "/charge", "mode=%72efund")).isEqualTo("charge");
            post(mvc, uri, null, null, firstHop(world, built, "payment#charge", "POST", uri, new byte[0], "rid-1"))
                    .andExpect(status().isForbidden())
                    .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
            assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
        });
    }

    /**
     * Where the request's parameters hold a form body's, as MockMvc's do, Spring's params condition reads them too,
     * while a caller's table matches the query alone: so a chain naming {@code charge} for a form body holding
     * {@code mode=refund} is refused.
     */
    @Test
    void formBodyConditionIsRefused(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        runPayment(world, (mvc, context) -> {
            byte[] body = "mode=refund".getBytes(StandardCharsets.UTF_8);
            post(mvc, "/charge", "application/x-www-form-urlencoded", body,
                    firstHop(world, built, "payment#charge", "POST", "/charge", body, "rid-1"))
                    .andExpect(status().isForbidden())
                    .andExpect(content().json("{\"reason\":\"BINDING_MISMATCH\"}", true));
            assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
        });
    }

    /**
     * On a {@code POST} Paztport's filter serves a form body's fields as parameters, so {@code mode=refund} in the
     * body makes Spring choose {@code refund}, while the filter named the operation from the query alone: whichever
     * the chain names, the request is refused and no handler runs. A chain naming {@code charge}, which Spring will
     * not run, is refused as the handler is about to run; one naming {@code refund} is refused by the filter's own
     * verification, since the operation named from the query is {@code charge}.
     */
    @Test
    void postFormBodyMeetingAConditionIsRefusedAtDispatch(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        ListAppender<ILoggingEvent> checked = new ListAppender<>();
        Logger check = (Logger) LoggerFactory.getLogger(DispatchCheck.class);
        onTomcat(world, built, form -> {
            // Attached once the application has started, since starting resets the loggers.
            checked.start();
            check.addAppender(checked);
            check.setLevel(Level.INFO);
            try {
                HttpResponse<String> named = form.send("POST", "payment#charge");
                assertThat(named.statusCode()).isEqualTo(403);
                assertThat(named.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
                assertThat(checked.list).as("refused as the handler was about to run, not by the filter")
                        .singleElement().satisfies(warning -> assertThat(warning.getFormattedMessage())
                                .contains("payment#charge").contains("payment#refund"));
                HttpResponse<String> other = form.send("POST", "payment#refund");
                assertThat(other.statusCode()).isEqualTo(403);
                assertThat(other.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            } finally {
                check.detachAppender(checked);
                check.setLevel(null);
            }
        });
        assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
    }

    /**
     * On a {@code PUT} Boot's form content filter, after Paztport's, adds a form body's fields to the parameters, so
     * {@code mode=refund} in the body makes Spring choose {@code amendRefund}, while the filter confirmed the
     * {@code amend} the chain named from the query alone: a request whose routing a body field changes is refused,
     * as the handler is about to run, and no handler runs.
     */
    @Test
    void putFormBodyMeetingAConditionIsRefusedAtDispatch(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        PolicyBuilder.Result built = world.write(OperationWorld.routes());
        PaymentHandlers.RAN.clear();
        ListAppender<ILoggingEvent> checked = new ListAppender<>();
        Logger check = (Logger) LoggerFactory.getLogger(DispatchCheck.class);
        onTomcat(world, built, form -> {
            // Attached once the application has started, since starting resets the loggers.
            checked.start();
            check.addAppender(checked);
            check.setLevel(Level.INFO);
            try {
                HttpResponse<String> answer = form.send("PUT", "payment#amend");
                assertThat(answer.statusCode()).isEqualTo(403);
                assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            } finally {
                check.detachAppender(checked);
                check.setLevel(null);
            }
        });
        assertThat(PaymentHandlers.RAN).as("no handler ran").isEmpty();
        assertThat(checked.list).as("refused as the handler was about to run, not by the filter").singleElement()
                .satisfies(warning -> assertThat(warning.getFormattedMessage()).contains("payment#amend")
                        .contains("payment#amendRefund"));
    }

    /** Sends a form body holding {@code mode=refund} to {@code /charge}. */
    private interface FormSender {
        /** Sends it as {@code method}, with gateway's first hop naming {@code rcv}. */
        HttpResponse<String> send(String method, String rcv) throws Exception;
    }

    private interface TomcatConsumer {
        void accept(FormSender form) throws Exception;
    }

    /** Runs payment on Tomcat, verifying gateway's requests under {@code enforce}, and hands {@code then} a sender. */
    private static void onTomcat(OperationWorld world, PolicyBuilder.Result built, TomcatConsumer then)
            throws Exception {
        byte[] body = "mode=refund".getBytes(StandardCharsets.UTF_8);
        try (ConfigurableApplicationContext app = new SpringApplicationBuilder(PaymentApp.class)
                .properties(world.service("payment", "server.port=0", "spring.main.banner-mode=off",
                        "paztport.verify=true", "paztport.mode=enforce", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-payment.json")))
                .run(); HttpClient http = TestHttp.newClient()) {
            URI uri = URI.create("http://127.0.0.1:" + app.getEnvironment().getProperty("local.server.port")
                    + "/charge");
            then.accept((method, rcv) -> {
                String[] hop = firstHop(world, built, rcv, method, "/charge", body, UUID.randomUUID().toString());
                HttpRequest.Builder request = TestHttp.request(uri)
                        .method(method, HttpRequest.BodyPublishers.ofByteArray(body))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header(PaztportHeaders.CHAIN, hop[0]);
                if (hop[1] != null) {
                    request.header(PaztportHeaders.PROOF, hop[1]);
                }
                if (hop[2] != null) {
                    request.header(PaztportHeaders.INFLUENCE, hop[2]);
                }
                return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            });
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({PaymentHandlers.Charges.class, PaymentHandlers.PayJson.class})
    static class PaymentApp {
    }
}
