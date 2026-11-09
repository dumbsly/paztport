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
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.TestHttp;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * On the real servlet container, a filter after Paztport's that changes the request's method or path, or dispatches
 * it elsewhere by a forward, an include or an async dispatch, makes the DispatcherServlet run another handler than
 * the operation Paztport's filter confirmed. The check made as the handler is about to run refuses it under
 * {@code enforce}, and elsewhere logs it and leaves the answer unattested; an honest request, a dispatch the confirmed
 * handler starts, a chain that names no operation, and the error page, pass it untouched. The test's filter can also
 * write a 401 itself ({@code deny}) or forward or include to another registered servlet ({@code servlet-forward},
 * {@code servlet-include}); an answer whose handler the check never saw is not attested where the chain named an
 * operation, nor is one that an interceptor of payment's own writes as it stops the request before the handler.
 * Whatever forwards the request, its answer is finished when the forward returns: sent whole, and attested where it
 * may be, where the forward writes into Paztport's buffer; whole and unattested behind another filter's wrapper that
 * does not buffer the body; and lost, unattested, behind one that does. A keyed operation's handler reached through a
 * percent-encoded segment is refused before it runs, the raw target giving no key value.
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

    /** Turns on Spring's method-override filter, which a service with its own table does not start beside. */
    private static final String HIDDEN_METHOD = "spring.mvc.hiddenmethod.filter.enabled=true";

    /** Starts orders verifying requests under {@code mode}. */
    private Service start(Path dir, String mode) throws IOException {
        return startWith(dir, "paztport.verify=true", "paztport.mode=" + mode);
    }

    /** Starts orders with {@code more}. */
    private Service startWith(Path dir, String... more) throws IOException {
        return capture(Service.start(dir, App.class, "orders", more));
    }

    /** Starts payment verifying requests under {@code mode}, then {@code more}. */
    private Service startPayment(Path dir, String mode, String... more) throws IOException {
        List<String> props = new ArrayList<>(List.of("paztport.verify=true", "paztport.mode=" + mode));
        props.addAll(List.of(more));
        return capture(Service.start(dir, PaymentApp.class, "payment", props.toArray(String[]::new)));
    }

    /** Captures the check's log once {@code service} has started, since starting would otherwise reset it. */
    private Service capture(Service service) {
        logged.start();
        log.addAppender(logged);
        log.setLevel(Level.INFO);
        return service;
    }

    @AfterAll
    static void closeClient() {
        http.close();
    }

    @Test
    void dispatchCheckRefusesARewrittenMethod(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("POST", "/orders", "orders#createOrder", "method");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            assertOneWarning("orders#createOrder", "none");
        }
    }

    @Test
    void dispatchCheckRefusesARewrittenPath(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search", "orders#search", "path");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            assertOneWarning("orders#search", "orders#getOrder");
        }
    }

    /**
     * A filter after Paztport's that forwards, so the request's own dispatch never reaches a handler. The container
     * closes the response when the forward returns, so the refusal is sent whole from there.
     */
    @Test
    void dispatchCheckRefusesAForward(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search", "orders#search", "forward");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(answer.headers().firstValue("Content-Type")).hasValue("application/json");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            assertOneWarning("orders#search", "orders#getOrder");
        }
    }

    @Test
    void dispatchCheckOnlyLogsAForwardUnderAudit(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "audit")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search", "orders#search", "forward");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("getOrder");
            assertThat(RAN).containsExactly("getOrder");
            assertThat(attestation(answer)).as("the other handler's answer is not attested").isNull();
            assertOneWarning("orders#search", "orders#getOrder");
        }
    }

    /** The confirmed handler ran first, so a forward it starts itself is not checked again. */
    @Test
    void dispatchCheckPassesAForwardItsHandlerStarts(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search?forward=yes", "orders#search", null);
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("getOrder");
            assertThat(attestation(answer)).as("the confirmed handler's answer is attested").isNotNull();
            assertThat(RAN).containsExactly("search", "getOrder");
            assertThat(logged.list).isEmpty();
        }
    }

    /** The answer finished when the forward returned is the one attested: its status and its whole body. */
    @Test
    void forwardedAnswerIsAttestedWhole(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            Service.Exchange exchange = orders.exchange("GET", "/orders/search?forward=yes", "orders#search", null);
            HttpWire.ResponseCheck check = HttpWire.verifyResponse(orders.gatewayVerifier(),
                    exchange.sent().chain(), exchange.sent().proof(), attestation(exchange.answer()), 200,
                    "getOrder".getBytes(StandardCharsets.UTF_8), "gateway", null);
            assertThat(check.result().reason()).isEqualTo(ReasonCode.OK);
        }
    }

    /** A forward the forwarded handler starts again: the innermost forward finishes the answer, once. */
    @Test
    void nestedForwardIsAttested(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search?forward=twice", "orders#search", null);
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("getOrder");
            assertThat(attestation(answer)).isNotNull();
            assertThat(RAN).containsExactly("search", "relay", "getOrder");
            assertThat(logged.list).isEmpty();
        }
    }

    /**
     * A filter after Paztport's that holds the response in its own buffer, as {@code ShallowEtagHeaderFilter} does:
     * the forwarded handler writes there, out of Paztport's sight, so the answer is not attested.
     */
    @Test
    void forwardBehindABufferingFilterIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search?forward=yes", "orders#search", "buffer");
            assertThat(answer.statusCode()).isEqualTo(200);
            // The buffering filter copies the body after the container has closed the response, so it is lost.
            assertThat(answer.body()).isEmpty();
            assertThat(attestation(answer)).isNull();
            assertThat(RAN).containsExactly("search", "getOrder");
        }
    }

    /** A filter after Paztport's that wraps the response without buffering: the answer is sent whole, unattested. */
    @Test
    void forwardBehindAWrapperIsSentWholeUnattested(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search?forward=yes", "orders#search", "wrap");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("getOrder");
            assertThat(attestation(answer)).isNull();
        }
    }

    /** A forwarded handler that throws leaves the error page to the container, and nothing is attested. */
    @Test
    void forwardedHandlerThatThrowsIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("GET", "/orders/search?forward=fail", "orders#search", null);
            assertThat(answer.statusCode()).isEqualTo(500);
            assertThat(attestation(answer)).isNull();
            assertThat(RAN).containsExactly("search", "getItem");
            assertThat(logged.list).isEmpty();
        }
    }

    /** A forward to a handler that answers from async work: its body is sent whole once that work completes. */
    @Test
    void forwardToAsyncWorkIsSentWhole(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment", "forward-async");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("later");
            assertThat(attestation(answer)).as("an async answer is not attested").isNull();
            assertThat(RAN).containsExactly("later");
        }
    }

    /** A form field reaches a handler on a {@code POST}, which the container would not parse once the body is read. */
    @Test
    void postFormFieldReachesTheHandler(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.sendBody("POST", "/echo", "payment", null,
                    "application/x-www-form-urlencoded", "field=hello");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("echo field=hello values=1");
        }
    }

    /** A {@code PUT} form's fields are added by Boot's form content filter alone, so the handler sees each once. */
    @Test
    void putFormFieldIsNotDoubled(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.sendBody("PUT", "/echo", "payment", null,
                    "application/x-www-form-urlencoded", "field=hello");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("echo field=hello values=1");
        }
    }

    /**
     * On a service with no table, beside Spring's method-override filter: that filter reads {@code _method} from the
     * {@code POST} form, which spends the body as the container would, so Boot's form content filter does not add the
     * fields again to the {@code PUT} it makes, and the handler sees each once. That filter adds its fields to the
     * request's own only where there is a query, so the request carries one.
     */
    @Test
    void overriddenPostFormFieldIsNotDoubled(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce", Service.NO_TABLE, HIDDEN_METHOD)) {
            HttpResponse<String> answer = payment.sendBody("POST", "/echo?source=form", "payment", null,
                    "application/x-www-form-urlencoded", "_method=PUT&field=hello");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("echo field=hello values=1");
            assertThat(RAN).containsExactly("echoPut");
        }
    }

    /** Once the form's fields are parameters, Spring builds a {@code POST} form's body from them for the handler. */
    @Test
    void spentPostFormBodyStillReachesTheHandler(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce", Service.NO_TABLE, HIDDEN_METHOD)) {
            HttpResponse<String> answer = payment.sendBody("POST", "/form-body", "payment", null,
                    "application/x-www-form-urlencoded", "field=hello");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("body field=hello");
        }
    }

    /**
     * A filter after Paztport's that includes another operation in place of the request's own dispatch. An included
     * handler cannot set the status, so the check owes the refusal and Paztport's filter writes it once the chain
     * returns; a second include after the first is refused too, so neither runs.
     */
    @Test
    void dispatchCheckRefusesAnInclude(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            for (String include : List.of("include", "include-twice")) {
                HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", include);
                assertThat(answer.statusCode()).as(include).isEqualTo(403);
                assertThat(answer.body()).as(include).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
                assertThat(answer.headers().firstValue("Content-Type")).as(include).hasValue("application/json");
                assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
                assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            }
            assertThat(logged.list).as("one line for each request's first include").hasSize(2);
            assertThat(logged.list).allSatisfy(warning -> assertThat(warning.getFormattedMessage())
                    .contains("payment#charge").contains("payment#refund"));
        }
    }

    /** On a service with no stamp key, which attests nothing and so holds no answer back, the include is refused. */
    @Test
    void dispatchCheckRefusesAnIncludeWithoutAttesting(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce", Service.NO_STAMP_KEY)) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "include");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertOneWarning("payment#charge", "payment#refund");
        }
    }

    @Test
    void dispatchCheckOnlyLogsAnIncludeUnderAudit(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "audit")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "include");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("refund");
            assertThat(RAN).containsExactly("refund");
            assertThat(attestation(answer)).as("the other handler's answer is not attested").isNull();
            assertOneWarning("payment#charge", "payment#refund");
        }
    }

    /**
     * A filter after Paztport's that includes another operation and then starts async work and dispatches it to the
     * request's own: the refusal the include owes is written before the async work goes on, and no handler runs.
     */
    @Test
    void dispatchCheckRefusesAnIncludeThenAnAsyncDispatch(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "include-then-async");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            assertOneWarning("payment#charge", "payment#refund");
        }
    }

    /** A filter after Paztport's that starts async work and dispatches it to another operation. */
    @Test
    void dispatchCheckRefusesAnAsyncDispatch(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "async");
            assertThat(answer.statusCode()).isEqualTo(403);
            assertThat(answer.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(RAN).as("neither the confirmed handler nor the other one ran").isEmpty();
            assertThat(attestation(answer)).as("the refusal is not attested").isNull();
            assertOneWarning("payment#charge", "payment#refund");
        }
    }

    /** The confirmed handler ran first, so an include it makes itself is not checked again. */
    @Test
    void dispatchCheckPassesAnIncludeItsHandlerStarts(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge?then=fragment", "payment#charge", null);
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("fragment");
            assertThat(RAN).containsExactly("charge", "fragment");
            assertThat(attestation(answer)).as("the confirmed handler's answer is attested").isNotNull();
            assertThat(logged.list).isEmpty();
        }
    }

    /** Async work the confirmed handler starts resumes on that handler, already checked. */
    @Test
    void dispatchCheckPassesAnAsyncRequestItsHandlerStarts(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge?then=async", "payment#charge", null);
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("charged later");
            assertThat(RAN).containsExactly("charge");
            assertThat(logged.list).isEmpty();
        }
    }

    /**
     * The error page is not checked: neither after the confirmed handler throws, nor where a filter after Paztport's
     * sends an error before any handler runs, so that the error page is the first handler the request reaches.
     */
    @Test
    void dispatchCheckPassesAnErrorPage(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> thrown = payment.send("POST", "/charge?then=fail", "payment#charge", null);
            assertThat(thrown.statusCode()).isEqualTo(500);
            assertThat(thrown.body()).doesNotContain("BINDING_MISMATCH").contains("\"status\":500");
            assertThat(RAN).containsExactly("charge");

            HttpResponse<String> sent = payment.send("POST", "/charge", "payment#charge", "error");
            assertThat(sent.statusCode()).isEqualTo(503);
            assertThat(sent.body()).doesNotContain("BINDING_MISMATCH").contains("\"status\":503");
            assertThat(RAN).containsExactly("charge");
            assertThat(logged.list).isEmpty();
        }
    }

    @Test
    void dispatchCheckPassesAnUnchangedRequest(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
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
        try (Service orders = start(dir, "enforce")) {
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
        try (Service orders = start(dir, "audit")) {
            HttpResponse<String> answer = orders.send("POST", "/orders", "orders#createOrder", "method");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("deleteOrders");
            assertThat(RAN).containsExactly("deleteOrders");
            assertOneWarning("orders#createOrder", "none");
        }
    }

    /** A rewritten request is served under audit, and its answer is not attested, while an honest one's is. */
    @Test
    void dispatchCheckWithholdsAttestationUnderAudit(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "audit")) {
            assertWithheldAttestation(orders);
        }
    }

    /** On a service that does not verify requests, whose verifier still decides attestation, the same holds. */
    @Test
    void dispatchCheckWithholdsAttestationWithoutVerifying(@TempDir Path dir) throws Exception {
        try (Service orders = startWith(dir, "paztport.verify=false")) {
            assertWithheldAttestation(orders);
        }
    }

    private void assertWithheldAttestation(Service orders) throws Exception {
        HttpResponse<String> honest = orders.send("POST", "/orders", "orders#createOrder", null);
        assertThat(honest.body()).isEqualTo("createOrder");
        assertThat(attestation(honest)).as("an honest request's answer is attested").isNotNull();
        assertThat(logged.list).isEmpty();

        HttpResponse<String> rewritten = orders.send("POST", "/orders", "orders#createOrder", "method");
        assertThat(rewritten.statusCode()).isEqualTo(200);
        assertThat(rewritten.body()).isEqualTo("deleteOrders");
        assertThat(attestation(rewritten)).as("the other handler's answer is not attested").isNull();
        assertOneWarning("orders#createOrder", "none");
    }

    /** A chain that names no operation had none confirmed, so a later rewrite contradicts nothing. */
    @Test
    void dispatchCheckIgnoresAChainNamingNoOperation(@TempDir Path dir) throws Exception {
        try (Service orders = start(dir, "enforce")) {
            HttpResponse<String> answer = orders.send("POST", "/orders", "orders", "method");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("deleteOrders");
            assertThat(attestation(answer)).as("verified under the service alone, whatever runs").isNotNull();
            assertThat(logged.list).isEmpty();
        }
    }

    /**
     * A filter that answers itself before any handler runs leaves the check nothing to confirm, so nothing to
     * attest.
     */
    @Test
    void filterWrittenAnswerIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "deny");
            assertThat(answer.statusCode()).isEqualTo(401);
            assertThat(answer.body()).isEqualTo("denied");
            assertThat(attestation(answer)).as("no handler was checked").isNull();
            assertThat(RAN).isEmpty();
            assertThat(logged.list).isEmpty();
        }
    }

    /** A chain that names no operation has none to vouch for, so the same answer is attested. */
    @Test
    void filterWrittenAnswerIsAttestedWithoutAnOperation(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment", "deny");
            assertThat(answer.statusCode()).isEqualTo(401);
            assertThat(answer.body()).isEqualTo("denied");
            assertThat(attestation(answer)).isNotNull();
        }
    }

    /**
     * An interceptor the application registers runs after the check and stops the request with its own answer
     * before the handler runs: the check confirmed the handler, but nothing the handler wrote is there to attest.
     */
    @Test
    void interceptorWrittenAnswerIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "intercept");
            assertThat(answer.statusCode()).isEqualTo(401);
            assertThat(answer.body()).isEqualTo("denied");
            assertThat(attestation(answer)).as("the handler was never reached").isNull();
            assertThat(RAN).isEmpty();
            assertThat(logged.list).isEmpty();
        }
    }

    /** A chain that names no operation has none to vouch for, so the interceptor's answer is attested. */
    @Test
    void interceptorWrittenAnswerIsAttestedWithoutAnOperation(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment", "intercept");
            assertThat(answer.statusCode()).isEqualTo(401);
            assertThat(answer.body()).isEqualTo("denied");
            assertThat(attestation(answer)).isNotNull();
            assertThat(RAN).isEmpty();
        }
    }

    /** Another registered servlet answers outside the check's sight, so its answer is not the operation's. */
    @Test
    void otherServletIncludedIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "servlet-include");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("legacy");
            assertThat(RAN).containsExactly("legacy");
            assertThat(attestation(answer)).isNull();
        }
    }

    /** Another registered servlet a filter forwards to: its answer is sent whole, and not attested. */
    @Test
    void otherServletForwardedIsNotAttested(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment#charge", "servlet-forward");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("legacy");
            assertThat(attestation(answer)).isNull();
        }
    }

    /** On a chain that names no operation, the same answer is attested, there being no operation to vouch for. */
    @Test
    void otherServletForwardedIsAttestedWithoutAnOperation(@TempDir Path dir) throws Exception {
        try (Service payment = startPayment(dir, "enforce")) {
            HttpResponse<String> answer = payment.send("POST", "/charge", "payment", "servlet-forward");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("legacy");
            assertThat(attestation(answer)).isNotNull();
        }
    }

    /** Payment's table where it holds items: {@code hold}, keyed by its item segment. */
    private static final OperationTable HOLDS = new OperationTable("payment", List.of(
            new OperationTable.Operation("hold", "POST", "/holds/{}", null, OperationTable.Key.segment(1))));

    /**
     * Spring matches a percent-encoded segment decoded, so {@code /holds/%41} reaches {@code hold}'s handler; the key
     * value is read from the raw target, where {@code %41} is none, so a chain naming {@code payment#hold} is refused
     * {@code BINDING_MISMATCH} and the handler never runs.
     */
    @Test
    void encodedSegmentIsRefused(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("ops-holds.json"), HOLDS.toFile());
        PaymentHandlers.RAN.clear();
        try (Service payment = capture(Service.start(dir, HoldsApp.class, "payment",
                List.of(List.of("gateway", "payment#hold"), HOLDS.route()), Service.NO_TABLE,
                "paztport.verify=true", "paztport.mode=enforce",
                "paztport.operations.table-path=" + dir.resolve("ops-holds.json")))) {
            HttpResponse<String> item = payment.send("POST", "/holds/A1", "payment#hold", null);
            assertThat(item.statusCode()).isEqualTo(200);
            assertThat(item.body()).isEqualTo("hold");

            HttpResponse<String> encoded = payment.send("POST", "/holds/%41", "payment#hold", null);
            assertThat(encoded.statusCode()).isEqualTo(403);
            assertThat(encoded.body()).isEqualTo("{\"reason\":\"BINDING_MISMATCH\"}");
            assertThat(attestation(encoded)).isNull();
            assertThat(PaymentHandlers.RAN).as("the handler ran for A1 alone").containsExactly("hold");
        }
    }

    private static String attestation(HttpResponse<String> answer) {
        return answer.headers().firstValue(PaztportHeaders.RESPONSE).orElse(null);
    }

    /** One WARN line, naming the operation confirmed and the one the handler is, and never the path. */
    private void assertOneWarning(String confirmed, String dispatched) {
        assertThat(logged.list).hasSize(1);
        ILoggingEvent warning = logged.list.get(0);
        assertThat(warning.getLevel()).isEqualTo(Level.WARN);
        assertThat(warning.getFormattedMessage()).contains(confirmed).contains(dispatched)
                .doesNotContain("/orders").doesNotContain("/items").doesNotContain("/charge");
    }

    /**
     * {@code name}, orders or payment, run as {@code app} with its own table, on a free port, with {@code more}
     * properties. Gateway may call each of its operations, and the service itself by a route that names none.
     */
    private record Service(ConfigurableApplicationContext app, OperationWorld world, PolicyBuilder.Result built,
            int port) implements AutoCloseable {

        /** A property that leaves the service without its stamp key, so that it attests nothing. */
        static final String NO_STAMP_KEY = "no-stamp-key";

        /** A property that leaves the service without its table, so that it names no operation. */
        static final String NO_TABLE = "no-table";

        static Service start(Path dir, Class<?> app, String name, String... more) throws IOException {
            return start(dir, app, name, List.of(), more);
        }

        /** As {@link #start(Path, Class, String, String...)}, with {@code moreRoutes} in the policy too. */
        static Service start(Path dir, Class<?> app, String name, List<List<String>> moreRoutes, String... more)
                throws IOException {
            OperationWorld world = new OperationWorld(dir);
            List<List<String>> routes = new ArrayList<>(OperationWorld.routes());
            routes.add(List.of("gateway", name));
            routes.addAll(moreRoutes);
            PolicyBuilder.Result built = world.write(routes);
            List<String> props = new ArrayList<>(List.of("server.port=0", "spring.main.banner-mode=off",
                    "paztport.origins=gateway"));
            props.addAll(List.of(more));
            if (!props.remove(NO_TABLE)) {
                props.add("paztport.operations.table-path=" + world.file("ops-" + name + ".json"));
            }
            boolean stampKey = !props.remove(NO_STAMP_KEY);
            String[] properties = Stream.of(world.service(name, props.toArray(String[]::new)))
                    .filter(p -> stampKey || !p.startsWith("paztport.key-path="))
                    .toArray(String[]::new);
            ConfigurableApplicationContext context = new SpringApplicationBuilder(app).properties(properties).run();
            return new Service(context, world, built,
                    Integer.parseInt(context.getEnvironment().getProperty("local.server.port")));
        }

        /** What gateway sent, its chain and proof, and the answer it got. */
        record Exchange(Stamper.Stamped sent, HttpResponse<String> answer) {
        }

        /**
         * Sends {@code method target} with gateway's first hop naming {@code rcv}, bound to the request as sent,
         * asking the test's filter for {@code rewrite} (one of {@link Rewrite}'s, or null for none).
         */
        HttpResponse<String> send(String method, String target, String rcv, String rewrite) throws Exception {
            return exchange(method, target, rcv, rewrite).answer();
        }

        /** As {@link #send}, with {@code body} as {@code contentType}, and the first hop bound over it. */
        HttpResponse<String> sendBody(String method, String target, String rcv, String rewrite, String contentType,
                String body) throws Exception {
            return exchange(method, target, rcv, rewrite, contentType, body.getBytes(StandardCharsets.UTF_8))
                    .answer();
        }

        /** As {@link #send}, keeping what gateway sent. */
        Exchange exchange(String method, String target, String rcv, String rewrite) throws Exception {
            return exchange(method, target, rcv, rewrite, null, new byte[0]);
        }

        private Exchange exchange(String method, String target, String rcv, String rewrite, String contentType,
                byte[] body) throws Exception {
            String rid = UUID.randomUUID().toString();
            Stamper.Stamped sent = new Stamper("gateway", "gw-1", world.gateway.getPrivate(), true, () -> rid,
                    System::currentTimeMillis).next(null, rcv, RequestBinding.compute(method, target, body),
                    List.of(), built.bundles().get("gateway"));
            HttpRequest.Builder request = TestHttp.request(URI.create("http://127.0.0.1:" + port + target))
                    .method(method, body.length == 0 ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofByteArray(body))
                    .header(PaztportHeaders.CHAIN, HttpWire.encodeChain(sent.chain()));
            String influence = HttpWire.encodeInfluence(List.of());
            if (influence != null) {
                request.header(PaztportHeaders.INFLUENCE, influence);
            }
            if (sent.proof() != null) {
                request.header(PaztportHeaders.PROOF, HttpWire.encodeProof(sent.proof()));
            }
            if (contentType != null) {
                request.header("Content-Type", contentType);
            }
            if (rewrite != null) {
                request.header(Rewrite.HEADER, rewrite);
            }
            return new Exchange(sent, http.send(request.build(), HttpResponse.BodyHandlers.ofString()));
        }

        /** Gateway's verifier, as a caller checks an answer's attestation with it. */
        Verifier gatewayVerifier() {
            long notAfter = OperationWorld.NOT_AFTER;
            return new Verifier(new VerifierConfig(
                    List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", world.gateway.getPublic(),
                            "orders", world.orders.getPublic(), "payment", world.payment.getPublic())), notAfter)),
                    List.of(new PinnedRoot(built.signedRoot().rootBytes(), built.signedRoot().rootId(), notAfter)),
                    notAfter, Set.of("gateway"), "", new InMemoryNonceCache(60_000), System::currentTimeMillis,
                    30_000, 300_000));
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

    /** Payment holding items, with {@code hold}'s handler alone. */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(PaymentHandlers.Holds.class)
    static class HoldsApp {
    }

    /** Payment, with its handlers and the same filter after Paztport's. */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({ChargeHandlers.class, PaymentHandlers.PayJson.class})
    static class PaymentApp {

        @Bean
        FilterRegistrationBean<Rewrite> rewrite() {
            return new FilterRegistrationBean<>(new Rewrite());
        }

        /**
         * An interceptor registered as an application registers one, so with the default order: it stops the request
         * with a 401 of its own where the test's header asks for {@code intercept}.
         */
        @Bean
        WebMvcConfigurer intercepting() {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(new HandlerInterceptor() {
                        @Override
                        public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                                Object handler) throws IOException {
                            if (!"intercept".equals(request.getHeader(Rewrite.HEADER))) {
                                return true;
                            }
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("text/plain");
                            response.getWriter().write("denied");
                            return false;
                        }
                    });
                }
            };
        }

        /** Another registered servlet, which the check does not see. */
        @Bean
        ServletRegistrationBean<HttpServlet> legacy() {
            return new ServletRegistrationBean<>(new HttpServlet() {
                @Override
                protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                    RAN.add("legacy");
                    resp.setContentType("text/plain");
                    resp.getWriter().write("legacy");
                }
            }, "/legacy");
        }
    }

    /**
     * Changes the request as the test's header asks: {@code method} turns {@code POST /orders} into
     * {@code DELETE /orders}, {@code path} turns any path into {@code /orders/123}, and {@code forward} forwards the
     * request there. On payment, {@code include} includes {@code POST /charge?mode=refund} in place of the request's
     * own dispatch, {@code include-twice} does so twice, {@code async} starts async work and dispatches it there,
     * {@code include-then-async} includes it and then starts async work and dispatches it to {@code /charge},
     * {@code error} sends an error before any handler runs, {@code deny} writes a 401 itself,
     * {@code servlet-forward} and {@code servlet-include} go to the servlet at {@code /legacy}, and
     * {@code forward-async} forwards to {@code /later}, which answers from async work; {@code intercept} passes the
     * request on for payment's own interceptor to stop. On either, {@code buffer}
     * holds the response in its own buffer and copies it once the chain returns, and {@code wrap} passes it on in a
     * wrapper that does not buffer.
     */
    static final class Rewrite extends OncePerRequestFilter {

        static final String HEADER = "X-Test-Rewrite";

        /** Payment's {@code refund}, on the same entrance as {@code charge}. */
        private static final String REFUND = "/charge?mode=refund";

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
            } else if ("forward".equals(rewrite)) {
                request.getRequestDispatcher("/orders/123").forward(request, response);
            } else if ("include".equals(rewrite)) {
                request.getRequestDispatcher(REFUND).include(request, response);
            } else if ("include-twice".equals(rewrite)) {
                request.getRequestDispatcher(REFUND).include(request, response);
                request.getRequestDispatcher(REFUND).include(request, response);
            } else if ("async".equals(rewrite)) {
                request.startAsync().dispatch(REFUND);
            } else if ("include-then-async".equals(rewrite)) {
                request.getRequestDispatcher(REFUND).include(request, response);
                request.startAsync().dispatch("/charge");
            } else if ("deny".equals(rewrite)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("text/plain");
                response.getWriter().write("denied");
            } else if ("servlet-forward".equals(rewrite)) {
                request.getRequestDispatcher("/legacy").forward(request, response);
            } else if ("servlet-include".equals(rewrite)) {
                request.getRequestDispatcher("/legacy").include(request, response);
            } else if ("forward-async".equals(rewrite)) {
                request.getRequestDispatcher("/later").forward(request, response);
            } else if ("buffer".equals(rewrite)) {
                ContentCachingResponseWrapper buffered = new ContentCachingResponseWrapper(response);
                chain.doFilter(request, buffered);
                buffered.copyBodyToResponse();
            } else if ("wrap".equals(rewrite)) {
                chain.doFilter(request, new HttpServletResponseWrapper(response));
            } else if ("error".equals(rewrite)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
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

    /** Orders' operations, each recording that it ran and answering its name, and two handlers in no table. */
    @RestController
    static class OrdersHandlers {

        @GetMapping("/orders/{id}")
        String getOrder(@PathVariable String id) {
            return ran("getOrder");
        }

        /**
         * Forwards itself when asked to: to {@code /orders/relay} for {@code twice}, to {@code /items/1}, which
         * throws, for {@code fail}, and to {@code /orders/123} for anything else.
         */
        @GetMapping("/orders/search")
        Object search(@RequestParam(required = false) String forward) {
            String name = ran("search");
            if (forward == null) {
                return name;
            }
            return switch (forward) {
                case "twice" -> new ModelAndView("forward:/orders/relay");
                case "fail" -> new ModelAndView("forward:/items/1");
                default -> new ModelAndView("forward:/orders/123");
            };
        }

        /** Mapped, and in no table: forwards to {@code /orders/123}. */
        @GetMapping("/orders/relay")
        ModelAndView relay() {
            ran("relay");
            return new ModelAndView("forward:/orders/123");
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
    }

    /**
     * Payment's operations on {@code /charge}, each recording that it ran, and two handlers in no table.
     * {@code charge} answers its name, or as {@code then} asks includes {@code /fragment}, answers from async work,
     * or throws so that the container dispatches the request to its error page.
     */
    @RestController
    static class ChargeHandlers {

        @PostMapping("/charge")
        Object charge(@RequestParam(required = false) String then, HttpServletRequest request,
                HttpServletResponse response) throws ServletException, IOException {
            ran("charge");
            if ("fragment".equals(then)) {
                request.getRequestDispatcher("/fragment").include(request, response);
                return null;
            }
            if ("async".equals(then)) {
                return (Callable<String>) () -> "charged later";
            }
            if ("fail".equals(then)) {
                throw new IllegalStateException("the handler failed");
            }
            return "charge";
        }

        @PostMapping(path = "/charge", params = "mode=refund")
        String refund() {
            return ran("refund");
        }

        @PutMapping("/charge")
        String amend() {
            return ran("amend");
        }

        @PutMapping(path = "/charge", params = "mode=refund")
        String amendRefund() {
            return ran("amendRefund");
        }

        /** Mapped, and in no table: answers the form field it was given, and how many values it had. */
        @PostMapping("/echo")
        String echoPost(@RequestParam(required = false) String field, HttpServletRequest request) {
            return echo("echo", field, request);
        }

        @PutMapping("/echo")
        String echoPut(@RequestParam(required = false) String field, HttpServletRequest request) {
            return echo("echoPut", field, request);
        }

        private static String echo(String name, String field, HttpServletRequest request) {
            String[] values = request.getParameterValues("field");
            ran(name);
            return "echo field=" + field + " values=" + (values == null ? 0 : values.length);
        }

        /** Mapped, and in no table: answers the body Spring hands it. */
        @PostMapping("/form-body")
        String formBody(@RequestBody String body) {
            ran("formBody");
            return "body " + body;
        }

        /** Mapped, and in no table. */
        @PostMapping("/fragment")
        String fragment() {
            return ran("fragment");
        }

        /** Mapped, and in no table: answers from async work. */
        @PostMapping("/later")
        Callable<String> later() {
            ran("later");
            return () -> "later";
        }
    }

    private static String ran(String name) {
        RAN.add(name);
        return name;
    }
}
