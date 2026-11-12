// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * The drain on a running server: {@code Connection: close} on every response for the drain window after the context
 * starts to close, and then the close itself. The application is started with {@code SpringApplication}, since each
 * test closes its own context.
 */
class DrainTest {

    /** Reads the whole answer to one request on a fresh connection, to the end of the stream. */
    private static String rawGet(int port, String path) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 2000);
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            // Without a Connection: close the server would keep the connection and this read would time out.
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    private static void awaitDraining(DrainState state) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!state.draining() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertThat(state.draining()).as("the drain has started").isTrue();
    }

    @Test
    void noHeaderBeforeShutdown() throws Exception {
        try (var ctx = DrainTestApp.start("--demo.drain-seconds=2")) {
            int port = port(ctx);
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/ping")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.headers().firstValue("Connection")).isEmpty();
        }
    }

    @Test
    void drainsBeforeGracefulShutdown() throws Exception {
        ConfigurableApplicationContext ctx = DrainTestApp.start("--demo.drain-seconds=2");
        int port = port(ctx);
        DrainState state = ctx.getBean(DrainState.class);
        long start = System.nanoTime();
        CompletableFuture<Void> closing = CompletableFuture.runAsync(ctx::close);
        awaitDraining(state);

        String answer = rawGet(port, "/ping");

        assertThat(answer).startsWith("HTTP/1.1 200");
        assertThat(answer.toLowerCase()).contains("connection: close");
        closing.get(10, TimeUnit.SECONDS);
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isGreaterThanOrEqualTo(1900);
    }

    @Test
    void inFlightRequestCompletesWithClose() throws Exception {
        ConfigurableApplicationContext ctx = DrainTestApp.start("--demo.drain-seconds=2");
        int port = port(ctx);
        DrainState state = ctx.getBean(DrainState.class);
        CompletableFuture<String> inFlight = CompletableFuture.supplyAsync(() -> {
            try {
                return rawGet(port, "/wait");
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        assertThat(DrainTestApp.HANDLER_ENTERED.await(5, TimeUnit.SECONDS)).isTrue();
        CompletableFuture<Void> closing = CompletableFuture.runAsync(ctx::close);
        awaitDraining(state);
        DrainTestApp.RELEASE.countDown();

        String answer = inFlight.get(10, TimeUnit.SECONDS);

        assertThat(answer).startsWith("HTTP/1.1 200");
        assertThat(answer.toLowerCase()).contains("connection: close");
        closing.get(10, TimeUnit.SECONDS);
    }

    @Test
    void zeroDisablesTheDrain() throws Exception {
        ConfigurableApplicationContext ctx = DrainTestApp.start("--demo.drain-seconds=0");
        int port = port(ctx);
        String before = rawGetKeepAlive(port);
        long start = System.nanoTime();
        ctx.close();
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(1500);
        assertThat(before.toLowerCase()).doesNotContain("connection: close");
    }

    private static int port(ConfigurableApplicationContext ctx) {
        return ((WebServerApplicationContext) ctx).getWebServer().getPort();
    }

    /** One request on a connection the server may keep; the read stops at the end of the body. */
    private static String rawGetKeepAlive(int port) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 2000);
            socket.setSoTimeout(5000);
            socket.getOutputStream().write("GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
            byte[] buffer = new byte[4096];
            int n = socket.getInputStream().read(buffer);
            return new String(buffer, 0, n, StandardCharsets.US_ASCII);
        }
    }
}
