// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.TestHttp;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * On the real servlet container, a filter after Paztport's that changes the request's method or path makes the
 * DispatcherServlet run another handler than the operation Paztport's filter confirmed. The check made as the handler
 * is about to run refuses it under {@code enforce} and only logs it under {@code audit}; an honest request, and the
 * error dispatch after a handler throws, pass it untouched.
 */
class DispatchCheckTest {

    private static final HttpClient http = TestHttp.newClient();

    /** The handlers that ran, by name, in order. */
    private static final List<String> RAN = new CopyOnWriteArrayList<>();

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger log = (Logger) LoggerFactory.getLogger(DispatchCheck.class);

    @BeforeEach
    void forget() {
        RAN.clear();
    }

    @AfterEach
    void detachLog() {
        log.detachAppender(logged);
        log.setLevel(null);
    }

    /** Starts orders under {@code mode}, then captures the check's log, which starting would otherwise reset. */
    private Orders start(Path dir, String mode) throws IOException {
        Orders orders = Orders.start(dir, mode);
        logged.start();
        log.addAppender(logged);
        log.setLevel(Level.INFO);
        return orders;
    }

    @AfterAll
    static void closeClient() {
        http.close();
    }

    @Test
    void dispatchCheckRefusesARewrittenMethod(@TempDir Path dir) throws Exception {
        try (Orders orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("POST", "/orders", "orders#createOrder", "method");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertOneWarning("orders#createOrder", "none");
        }
    }

    @Test
    void dispatchCheckRefusesARewrittenPath(@TempDir Path dir) throws Exception {
        try (Orders orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search", "orders#search", "path");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertOneWarning("orders#search", "orders#getOrder");
        }
    }

    @Test
    void dispatchCheckPassesAnUnchangedRequest(@TempDir Path dir) throws Exception {
        try (Orders orders = start(dir, "enforce")) {
            HttpResponse<String> created = orders.send("POST", "/orders", "orders#createOrder", null);
            assertThat(created.statusCode()).isEqualTo(200);
            assertThat(created.body()).isEqualTo("createOrder");
            HttpResponse<String> found = orders.send("GET", "/orders/123", "orders#getOrder", null);
            assertThat(found.statusCode()).isEqualTo(200);
            assertThat(found.body()).isEqualTo("getOrder");
            assertThat(RAN).containsExactly("createOrder", "getOrder");
            assertThat(logged.list).isEmpty();
        }
    }

    @Test
    void dispatchCheckIgnoresErrorDispatch(@TempDir Path dir) throws Exception {
        try (Orders orders = start(dir, "enforce")) {
            // The error dispatch still carries what the filter recorded, while /error is another handler.
            HttpResponse<String> answer = orders.send("GET", "/items/42", "orders#getItem", null);
            assertThat(answer.statusCode()).isEqualTo(500);
            assertThat(answer.body()).doesNotContain("BINDING_MISMATCH").contains("\"status\":500");
            assertThat(RAN).containsExactly("getItem");
            assertThat(logged.list).isEmpty();
        }
    }

    @Test
    void dispatchCheckOnlyLogsUnderAudit(@TempDir Path dir) throws Exception {
        try (Orders orders = start(dir, "audit")) {
            HttpResponse<String> answer = orders.send("POST", "/orders", "orders#createOrder", "method");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("deleteOrders");
            assertThat(RAN).containsExactly("deleteOrders");
            assertOneWarning("orders#createOrder", "none");
        }
    }

    /** One WARN line, naming the operation confirmed and the one the handler is, and never the path. */
    private void assertOneWarning(String confirmed, String dispatched) {
        assertThat(logged.list).hasSize(1);
        ILoggingEvent warning = logged.list.get(0);
        assertThat(warning.getLevel()).isEqualTo(Level.WARN);
        assertThat(warning.getFormattedMessage()).contains(confirmed).contains(dispatched)
                .doesNotContain("/orders").doesNotContain("/items");
    }

    /** Orders, verifying gateway's requests and holding its own table, on a free port. */
    private record Orders(ConfigurableApplicationContext app, OperationWorld world, PolicyBuilder.Result built,
            int port) implements AutoCloseable {

        static Orders start(Path dir, String mode) throws IOException {
            OperationWorld world = new OperationWorld(dir);
            PolicyBuilder.Result built = world.write(OperationWorld.routes());
            ConfigurableApplicationContext app = new SpringApplicationBuilder(App.class)
                    .properties(world.service("orders", "server.port=0", "spring.main.banner-mode=off",
                            "paztport.verify=true", "paztport.mode=" + mode, "paztport.origins=gateway",
                            "paztport.operations.table-path=" + world.file("ops-orders.json")))
                    .run();
            return new Orders(app, world, built,
                    Integer.parseInt(app.getEnvironment().getProperty("local.server.port")));
        }

        /**
         * Sends {@code method target} with gateway's first hop naming {@code rcv}, bound to the request as sent,
         * asking the test's filter for {@code rewrite} ({@code method}, {@code path}, or null for none).
         */
        HttpResponse<String> send(String method, String target, String rcv, String rewrite) throws Exception {
            String rid = UUID.randomUUID().toString();
            Stamper.Stamped sent = new Stamper("gateway", "gw-1", world.gateway.getPrivate(), true, () -> rid,
                    System::currentTimeMillis).next(null, rcv, RequestBinding.compute(method, target, new byte[0]),
                    List.of(), built.bundles().get("gateway"));
            HttpRequest.Builder request = TestHttp.request(URI.create("http://127.0.0.1:" + port + target))
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .header(PaztportHeaders.CHAIN, HttpWire.encodeChain(sent.chain()));
            String influence = HttpWire.encodeInfluence(List.of());
            if (influence != null) {
                request.header(PaztportHeaders.INFLUENCE, influence);
            }
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
    @Import(OrdersHandlers.class)
    static class App {

        /** Registered as an application registers a filter, so it runs after Paztport's. */
        @Bean
        FilterRegistrationBean<Rewrite> rewrite() {
            return new FilterRegistrationBean<>(new Rewrite());
        }
    }

    /**
     * Changes the request as the test's header asks: {@code method} turns {@code POST /orders} into
     * {@code DELETE /orders}, and {@code path} turns any path into {@code /orders/123}.
     */
    static final class Rewrite extends OncePerRequestFilter {

        static final String HEADER = "X-Test-Rewrite";

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String rewrite = request.getHeader(HEADER);
            if ("method".equals(rewrite)) {
                chain.doFilter(new HttpServletRequestWrapper(request) {
                    @Override
                    public String getMethod() {
                        return "DELETE";
                    }
                }, response);
            } else if ("path".equals(rewrite)) {
                chain.doFilter(new HttpServletRequestWrapper(request) {
                    @Override
                    public String getRequestURI() {
                        return "/orders/123";
                    }

                    @Override
                    public StringBuffer getRequestURL() {
                        return new StringBuffer("http://127.0.0.1/orders/123");
                    }

                    @Override
                    public String getServletPath() {
                        return "/orders/123";
                    }
                }, response);
            } else {
                chain.doFilter(request, response);
            }
        }
    }

    /** Orders' operations, each recording that it ran and answering its name, and one handler in no table. */
    @RestController
    static class OrdersHandlers {

        @GetMapping("/orders/{id}")
        String getOrder(@PathVariable String id) {
            return ran("getOrder");
        }

        @GetMapping("/orders/search")
        String search() {
            return ran("search");
        }

        @PostMapping("/orders")
        String createOrder() {
            return ran("createOrder");
        }

        /** Throws, so that the container dispatches the request to its error page. */
        @GetMapping("/items/{id:\\d+}")
        String getItem(@PathVariable String id) {
            ran("getItem");
            throw new IllegalStateException("the handler failed");
        }

        /** Mapped, and in no table. */
        @DeleteMapping("/orders")
        String deleteOrders() {
            return ran("deleteOrders");
        }

        private static String ran(String name) {
            RAN.add(name);
            return name;
        }
    }
}
