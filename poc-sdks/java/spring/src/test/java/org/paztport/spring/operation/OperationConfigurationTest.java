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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
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
        runner.withPropertyValues(world.service("orders", "paztport.verify=true", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-orders.json")))
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
        Stamper.Stamped sent = new Stamper("gateway", "gw-1", world.gateway.getPrivate(), true, () -> rid,
                System::currentTimeMillis).next(null, rcv, RequestBinding.compute("GET", uri, new byte[0]), List.of(),
                built.bundles().get("gateway"));
        return new String[] {HttpWire.encodeChain(sent.chain()),
            sent.proof() == null ? null : HttpWire.encodeProof(sent.proof()), HttpWire.encodeInfluence(List.of())};
    }

    private static ResultActions send(MockMvc mvc, String uri, String[] hop) throws Exception {
        // A URI, not a template, so that a percent-encoded path is sent as it stands.
        MockHttpServletRequestBuilder request = get(URI.create(uri)).header(PaztportHeaders.CHAIN, hop[0]);
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
}
