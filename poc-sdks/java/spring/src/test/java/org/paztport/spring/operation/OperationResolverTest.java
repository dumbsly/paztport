// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.OperationTable.Operation;
import org.paztport.spring.PaztportAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.ContextConsumer;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.HandlerMapping;

/**
 * The receiver's operation is the one its framework will dispatch the request to, worked out from Spring's own
 * handler mappings before the handler runs, never from matching the path against the table: so a path that Spring
 * and a caller match differently (a regex variable, a trailing slash) has no operation, or another one, and a chain
 * that names the caller's choice is refused.
 */
class OperationResolverTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class, PaztportAutoConfiguration.class))
            .withUserConfiguration(Handlers.class);

    /** Runs payment with its table and {@code handlers}, verifying requests from gateway. */
    private void runPayment(OperationWorld world, List<Class<?>> handlers,
            ContextConsumer<AssertableWebApplicationContext> then) {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class,
                        PaztportAutoConfiguration.class))
                .withUserConfiguration(handlers.toArray(Class<?>[]::new))
                .withPropertyValues(world.service("payment", "paztport.verify=true", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-payment.json")))
                .run(then);
    }

    /** {@code method uri} as MockMvc builds it, its query read into parameters as the container reads it. */
    private static MockHttpServletRequest built(AssertableWebApplicationContext context, String method,
            String uri) {
        return MockMvcRequestBuilders.request(method, URI.create(uri)).buildRequest(context.getServletContext());
    }

    /** Runs orders with {@code table} as its own table, verifying requests from gateway. */
    private void runOrders(OperationWorld world, Path table, ContextConsumer<AssertableWebApplicationContext> then) {
        runner.withPropertyValues(world.service("orders", "paztport.verify=true", "paztport.origins=gateway",
                "paztport.operations.table-path=" + table)).run(then);
    }

    private static MockHttpServletRequest request(AssertableWebApplicationContext context, String method,
            String uri) {
        return new MockHttpServletRequest(context.getServletContext(), method, uri);
    }

    @Test
    void resolvesTheDispatchedOperation(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runOrders(world, world.file("ops-orders.json"), context -> {
            assertThat(context).hasNotFailed();
            OperationResolver resolver = context.getBean(OperationResolver.class);
            assertThat(resolver.operationFor(request(context, "GET", "/orders/123"))).isEqualTo("getOrder");
            assertThat(resolver.operationFor(request(context, "GET", "/orders/search"))).isEqualTo("search");
            assertThat(resolver.operationFor(request(context, "POST", "/orders"))).isEqualTo("createOrder");
            assertThat(resolver.operationFor(request(context, "GET", "/debug"))).as("mapped, not in the table")
                    .isNull();
            assertThat(resolver.operationFor(request(context, "GET", "/orders/"))).as("Spring 7 matches no "
                    + "trailing slash, so the request goes to no operation's handler").isNull();
            assertThat(resolver.operationFor(request(context, "DELETE", "/orders/123"))).as("no handler for the "
                    + "method").isNull();
            // Spring matches the decoded segment, where a caller matches the raw path: the handler decides.
            assertThat(resolver.operationFor(request(context, "GET", "/orders/%73earch"))).isEqualTo("search");

            MockHttpServletRequest request = request(context, "GET", "/orders/123");
            request.setAttribute("application", "kept");
            List<String> before = Collections.list(request.getAttributeNames());
            assertThat(resolver.operationFor(request)).isEqualTo("getOrder");
            assertThat(request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE)).isNull();
            assertThat(Collections.list(request.getAttributeNames())).as("the request's attributes are as they "
                    + "were").isEqualTo(before);
            assertThat(request.getAttribute("application")).isEqualTo("kept");
        });
    }

    @Test
    void regexVariableNormalises(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runOrders(world, world.file("ops-orders.json"), context -> {
            OperationResolver resolver = context.getBean(OperationResolver.class);
            assertThat(resolver.operationFor(request(context, "GET", "/items/42"))).isEqualTo("getItem");
            assertThat(resolver.operationFor(request(context, "GET", "/items/abc"))).as("the table matches it, "
                    + "the handler's regex does not").isNull();
        });
    }

    /**
     * The pattern is the one {@code BEST_MATCHING_PATTERN_ATTRIBUTE} holds once the DispatcherServlet has dispatched
     * to an annotated handler, as {@code PartnerGate} reads it. A request that goes to static resources instead, whose
     * mapping sets its pattern only as the handler is about to run, has none here, so no operation.
     */
    @Test
    void thePatternIsTheOneTheDispatcherServletSets(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runOrders(world, world.file("ops-orders.json"), context -> {
            OperationResolver resolver = context.getBean(OperationResolver.class);
            MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
            for (String uri : List.of("/orders/123", "/orders/search", "/items/42", "/debug")) {
                assertThat(resolver.patternFor(request(context, "GET", uri))).as(uri)
                        .isEqualTo(dispatchedPattern(mvc, uri)).isNotNull();
            }
            for (String uri : List.of("/items/abc", "/orders/")) {
                assertThat(dispatchedPattern(mvc, uri)).as(uri).isEqualTo("/**");
                assertThat(resolver.patternFor(request(context, "GET", uri))).as(uri).isNull();
            }
        });
    }

    private static Object dispatchedPattern(MockMvc mvc, String uri) throws Exception {
        List<Object> dispatched = new ArrayList<>();
        mvc.perform(MockMvcRequestBuilders.get(uri)).andDo(result -> dispatched.add(
                result.getRequest().getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE)));
        return dispatched.get(0);
    }

    @Test
    void aPatternNormalisesToATemplateOnlyWhenEachSegmentIsLiteralOrAWholeVariable() {
        assertThat(OperationResolver.template("/")).isEqualTo("/");
        assertThat(OperationResolver.template("/orders")).isEqualTo("/orders");
        assertThat(OperationResolver.template("/orders/{id}")).isEqualTo("/orders/{}");
        assertThat(OperationResolver.template("/items/{id:\\d+}")).isEqualTo("/items/{}");
        assertThat(OperationResolver.template("/items/{id:\\d{3}}/x")).isEqualTo("/items/{}/x");
        assertThat(OperationResolver.template("/a/{x:b*}")).isEqualTo("/a/{}");
        for (String none : List.of("", "orders", "/files/*", "/files/**", "/files/{*rest}", "/a/x{id}",
                "/a/{x}-{y}", "/a/{x}{y}", "/a/{x}.json", "/a?c", "/orders/", "//orders", "/a/{x")) {
            assertThat(OperationResolver.template(none)).as(none).isNull();
        }
    }

    @Test
    void startFailsWhenATableOperationHasNoMapping(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        List<Operation> operations = new ArrayList<>(OperationWorld.ORDERS.operations());
        operations.add(new Operation("deleteOrder", "DELETE", "/orders/{}"));
        OperationTable unmapped = new OperationTable("orders", operations);
        List<List<String>> routes = OperationWorld.routesWithout(OperationWorld.ORDERS.route());
        routes.add(unmapped.route());
        world.write(routes);
        Files.writeString(dir.resolve("ops-orders-delete.json"), unmapped.toFile());
        runOrders(world, world.file("ops-orders-delete.json"), context -> assertThat(context).getFailure()
                .hasMessageContaining("deleteOrder").hasMessageContaining("DELETE /orders/{}"));
    }

    // --- The operation is the handler that runs ---

    /** The query condition Spring routes by, not the path alone, decides which of an entrance's operations it is. */
    @Test
    void resolvesTheHandlerNotThePath(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runPayment(world, List.of(PaymentHandlers.Charges.class, PaymentHandlers.PayJson.class), context -> {
            assertThat(context).hasNotFailed();
            OperationResolver resolver = context.getBean(OperationResolver.class);
            assertThat(resolver.operationFor(built(context, "POST", "/charge?mode=refund"))).isEqualTo("refund");
            assertThat(resolver.operationFor(built(context, "POST", "/charge"))).isEqualTo("charge");
            assertThat(resolver.operationFor(built(context, "POST", "/charge?mode=x"))).as("the condition does not "
                    + "hold, so the handler with none runs").isEqualTo("charge");
        });
    }

    @Test
    void startAcceptsConsumesAloneOnItsEntrance(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runPayment(world, List.of(PaymentHandlers.Charges.class, PaymentHandlers.PayJson.class), context -> {
            assertThat(context).hasNotFailed();
            MockHttpServletRequest json = built(context, "POST", "/pay");
            json.setContentType("application/json");
            assertThat(context.getBean(OperationResolver.class).operationFor(json)).isEqualTo("pay");
        });
    }

    @Test
    void startAcceptsAHandlerMappedWithNoMethod(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runPayment(world, List.of(PaymentHandlers.Charges.class, PaymentHandlers.PayAnyMethod.class), context -> {
            assertThat(context).hasNotFailed();
            OperationResolver resolver = context.getBean(OperationResolver.class);
            assertThat(resolver.operationFor(built(context, "POST", "/pay"))).isEqualTo("pay");
            assertThat(resolver.operationFor(built(context, "GET", "/pay"))).as("the table has no GET /pay")
                    .isNull();
        });
    }

    /** A second {@code POST /orders} handler that only its media type tells apart from {@code createOrder}. */
    @RestController
    static class CreateOrderAsJson {

        @PostMapping(path = "/orders", consumes = "application/json")
        String createOrderAsJson() {
            return "createOrderAsJson";
        }
    }

    @Test
    void startRefusesAnEntranceToldApartByConsumes(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runner.withUserConfiguration(CreateOrderAsJson.class).withPropertyValues(world.service("orders",
                        "paztport.verify=true", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-orders.json")))
                .run(context -> assertThat(context).getFailure()
                        .hasMessageContaining("paztport.operations.table-path")
                        .hasMessageContaining("POST /orders").hasMessageContaining("createOrder"));
    }

    /** A {@code POST /charge} handler for a request without the parameter, a condition the table cannot hold. */
    @RestController
    static class ChargeWithoutMode {

        @PostMapping(path = "/charge", params = "!mode")
        String chargeWithoutMode() {
            return "chargeWithoutMode";
        }
    }

    @Test
    void startRefusesAConditionTheTableCannotExpress(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runPayment(world, List.of(PaymentHandlers.Charges.class, PaymentHandlers.PayJson.class,
                ChargeWithoutMode.class), context -> assertThat(context).getFailure()
                        .hasMessageContaining("paztport.operations.table-path")
                        .hasMessageContaining("POST /charge").hasMessageContaining("!mode"));
    }

    /** A second {@code GET /items/{}} handler, which Spring tells apart from {@code getItem} by its regex alone. */
    @RestController
    static class ItemByName {

        @GetMapping("/items/{name:[a-z]+}")
        String itemByName(@PathVariable String name) {
            return "itemByName";
        }
    }

    @Test
    void startRefusesATableOperationOfTwoHandlers(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runner.withUserConfiguration(ItemByName.class).withPropertyValues(world.service("orders",
                        "paztport.verify=true", "paztport.origins=gateway",
                        "paztport.operations.table-path=" + world.file("ops-orders.json")))
                .run(context -> assertThat(context).getFailure()
                        .hasMessageContaining("paztport.operations.table-path")
                        .hasMessageContaining("getItem").hasMessageContaining("GET /items/{}"));
    }

    /** Only {@code charge} on {@code POST /charge}: no handler has {@code refund}'s condition. */
    @RestController
    static class ChargeOnly {

        @PostMapping("/charge")
        String charge() {
            return "charge";
        }
    }

    @Test
    void startRefusesATableOperationOfNone(@TempDir Path dir) throws Exception {
        OperationWorld world = new OperationWorld(dir);
        world.write(OperationWorld.routes());
        runPayment(world, List.of(ChargeOnly.class, PaymentHandlers.PayJson.class), context -> assertThat(context)
                .getFailure().hasMessageContaining("paztport.operations.table-path")
                .hasMessageContaining("refund").hasMessageContaining("POST /charge"));
    }
}
