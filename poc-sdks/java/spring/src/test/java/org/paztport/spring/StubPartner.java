// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.SessionReply;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.core.SignedRoot;
import org.paztport.http.HttpSessions;

/**
 * A partner organisation reduced to what the egress sees: a JDK server on a loopback port, over plain HTTP, that
 * answers the session handshake with a reply signed by a partner policy key and answers every other path with a
 * status and body the test sets. It records every request it receives, so a test can prove that nothing at all was
 * sent.
 *
 * <p>A request with no client root always gets an unsafe reply, as a real partner would give it. Otherwise the
 * reply carries the status the test chose, and is signed by the partner's key unless the test asked for one
 * handshake to be signed by another key, which the egress sees as {@code PIN_MISMATCH}.
 */
final class StubPartner implements AutoCloseable {

    /** One request as received: the headers' names are lower-cased. */
    record Received(String method, String path, Map<String, List<String>> headers, byte[] body) {
        String header(String name) {
            List<String> values = headers.get(name.toLowerCase());
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        boolean isHandshake() {
            return path.equals(HttpSessions.PATH);
        }
    }

    private record Answer(int status, String body) {
    }

    final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final SignedRoot root;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final List<String> issued = new CopyOnWriteArrayList<>();
    private final Deque<KeyPair> nextSigners = new ArrayDeque<>();
    private final Deque<Answer> nextAnswers = new ArrayDeque<>();
    private volatile String status = "attested";
    private volatile long handshakeDelayMs;

    StubPartner() throws IOException {
        root = PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, policy.getPrivate()).signedRoot();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    /** {@code http://127.0.0.1:<port>}. */
    URI url() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** The pin the egress holds for this partner. */
    String policyKey() {
        return Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
    }

    /** The status a request with a client root gets: {@code attested} or {@code unsafe}. */
    void status(String status) {
        this.status = status;
    }

    /** The next handshake is signed, and names its policy key, as {@code key}. */
    synchronized void signNextHandshakeWith(KeyPair key) {
        nextSigners.add(key);
    }

    /** The next non-handshake request gets this status and body instead of {@code 200 {"ok":true}}. */
    synchronized void answerNext(int status, String body) {
        nextAnswers.add(new Answer(status, body));
    }

    /** Holds every handshake this long before answering, so concurrent first calls overlap it. */
    void handshakeDelayMs(long ms) {
        this.handshakeDelayMs = ms;
    }

    List<Received> received() {
        return List.copyOf(received);
    }

    List<Received> handshakes() {
        return received.stream().filter(Received::isHandshake).toList();
    }

    List<Received> calls() {
        return received.stream().filter(r -> !r.isHandshake()).toList();
    }

    /** The session ids this partner has issued, in order. */
    List<String> issued() {
        return List.copyOf(issued);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] body = exchange.getRequestBody().readAllBytes();
            Map<String, List<String>> headers = new HashMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), List.copyOf(v)));
            Received r = new Received(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath(),
                    Map.copyOf(headers), body);
            received.add(r);
            if (r.isHandshake()) {
                if (handshakeDelayMs > 0) {
                    try {
                        Thread.sleep(handshakeDelayMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                send(exchange, 200, reply(HttpSessions.parseRequest(body)).toJson().toString());
                return;
            }
            Answer answer;
            synchronized (this) {
                answer = nextAnswers.poll();
            }
            if (answer == null) {
                answer = new Answer(200, "{\"ok\":true}");
            }
            send(exchange, answer.status(), answer.body());
        }
    }

    private SessionReply reply(SessionRequest req) {
        KeyPair signer;
        synchronized (this) {
            signer = nextSigners.isEmpty() ? policy : nextSigners.poll();
        }
        SignedRoot serverRoot = signer == policy ? root
                : PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, signer.getPrivate()).signedRoot();
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                serverRoot.sig(), req.nonce(), nonce, req.clientPolicyKey(), req.clientKeyring());
        issued.add(sess);
        String replyStatus = req.clientRoot() == null ? "unsafe" : status;
        return Sessions.signReply(new SessionReply(serverRoot,
                Base64Url.encode(Crypto.encodePublicKey(signer.getPublic())),
                Map.of("psp", Base64Url.encode(Crypto.encodePublicKey(signer.getPublic()))), nonce, sess,
                replyStatus, replyStatus.equals("unsafe") ? List.of("POST /refund") : List.of(), null),
                signer.getPrivate());
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /** Stops answering; a second close does nothing. */
    @Override
    public synchronized void close() {
        if (executor.isShutdown()) {
            return;
        }
        server.stop(0);
        executor.shutdownNow();
    }
}
