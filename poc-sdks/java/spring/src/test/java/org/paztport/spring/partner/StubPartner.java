// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.http.HttpSessions;
import org.paztport.http.SilentPeer;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;

/**
 * A partner organisation reduced to what the egress sees: a JDK server on a loopback port, over plain HTTP or,
 * where the auto-configured egress needs it, over HTTPS with a certificate from the fixture CA, that answers the
 * session handshake with a signed reply and answers every other path with a status and body the test sets. It
 * records every request it receives, so a test can prove that nothing at all was sent.
 *
 * <p>Its entry service is {@code psp}. By default a reply is in the entry-key form: signed by {@code psp}'s key,
 * carrying the policy key's signature over the keyring and a reply certificate for that key, whose expiry a test
 * can set. A test can ask for the policy-key form instead, signed by the policy key with neither field.
 *
 * <p>A request with no client root always gets an unsafe reply, as a real partner would give it. Otherwise the
 * reply carries the status the test chose, and is signed by the partner's key unless the test asked for one
 * handshake to be signed by another key, which the egress sees as {@code PIN_MISMATCH}.
 */
final class StubPartner implements AutoCloseable {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

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
    /** The entry service {@code psp}'s key, which signs entry-key replies. */
    final KeyPair entry = Crypto.generateEd25519KeyPair();
    private final KeyringFile keyring = KeyringFile.sign(Map.of("psp", pub(entry)), pub(policy),
            NOT_AFTER, policy.getPrivate());
    private final SignedRoot root;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final List<String> issued = new CopyOnWriteArrayList<>();
    private final Deque<KeyPair> nextSigners = new ArrayDeque<>();
    private final Deque<Answer> nextAnswers = new ArrayDeque<>();
    private final Deque<Integer> handshakeFailures = new ArrayDeque<>();
    private final Deque<SilentPeer.Stall> nextStalls = new ArrayDeque<>();
    private final CountDownLatch closed = new CountDownLatch(1);
    private volatile String status = "attested";
    private volatile long handshakeDelayMs;
    private volatile boolean policyKeyForm;
    private volatile long replyCertNotAfter = System.currentTimeMillis() + 7 * 86_400_000L;
    private final List<SessionReply> replies = new CopyOnWriteArrayList<>();

    /** Over plain HTTP. */
    StubPartner() throws IOException {
        this(false);
    }

    /**
     * @param tls over HTTPS, presenting the fixture certificate for {@code 127.0.0.1} under the fixture CA, which
     *     the egress's bundle trusts; it asks for no client certificate
     */
    StubPartner(boolean tls) throws IOException {
        root = PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, NOT_AFTER, policy.getPrivate()).signedRoot();
        InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        if (tls) {
            HttpsServer https = HttpsServer.create(loopback, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(SslBundle.of(new PemSslStoreBundle(
                    PemSslStoreDetails.forCertificate("classpath:tls/payment.crt")
                            .withPrivateKey("classpath:tls/payment.key"),
                    PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))).createSslContext()));
            server = https;
        } else {
            server = HttpServer.create(loopback, 0);
        }
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    /** {@code http://127.0.0.1:<port>}, or {@code https://} over TLS. */
    URI url() {
        return URI.create((server instanceof HttpsServer ? "https" : "http") + "://127.0.0.1:"
                + server.getAddress().getPort());
    }

    /** The pin the egress holds for this partner. */
    String policyKey() {
        return pub(policy);
    }

    /** Replies are signed by the policy key, with no keyring signature or reply certificate. */
    void policyKeyForm() {
        this.policyKeyForm = true;
    }

    /** The {@code notAfter} of the reply certificate in each entry-key reply from now on. */
    void replyCertNotAfter(long notAfter) {
        this.replyCertNotAfter = notAfter;
    }

    /** Every handshake reply sent, in order. */
    List<SessionReply> replies() {
        return List.copyOf(replies);
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

    /**
     * The next non-handshake request is never finished: it gets no answer, or a 200's headers and the start of a
     * body, as {@code stall} says, and then nothing until this partner is closed.
     */
    synchronized void stallNextCall(SilentPeer.Stall stall) {
        nextStalls.add(stall);
    }

    /** The next handshake with a client root is answered with this status and no body, as a failing partner's. */
    synchronized void failNextHandshake(int status) {
        handshakeFailures.add(status);
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
                SessionRequest req = SessionRequest.parse(body);
                Integer failure;
                synchronized (this) {
                    failure = req.clientRoot() == null ? null : handshakeFailures.poll();
                }
                if (failure != null) {
                    send(exchange, failure, "");
                    return;
                }
                send(exchange, 200, reply(req).toJson());
                return;
            }
            SilentPeer.Stall stall;
            Answer answer;
            synchronized (this) {
                stall = nextStalls.poll();
                answer = stall == null ? nextAnswers.poll() : null;
            }
            if (stall != null) {
                stall(exchange, stall);
                return;
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
                : PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4,
                        NOT_AFTER, signer.getPrivate()).signedRoot();
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                serverRoot.sig(), req.nonce(), nonce, req.clientPolicyKey(), req.clientKeyring());
        issued.add(sess);
        String replyStatus = req.clientRoot() == null ? "unsafe" : status;
        List<String> disabled = replyStatus.equals("unsafe") ? List.of("POST /refund") : List.of();
        SessionReply reply;
        if (signer != policy || policyKeyForm) {
            reply = Sessions.signReply(new SessionReply(serverRoot, pub(signer), keyring.services(), null, null, null,
                    nonce, sess, replyStatus, disabled, null), signer.getPrivate());
        } else {
            ReplyCert cert = ReplyCert.issue(pub(policy), "psp", pub(entry), replyCertNotAfter, policy.getPrivate());
            reply = Sessions.signReply(new SessionReply(serverRoot, pub(policy), keyring.services(), keyring.sig(),
                    keyring.notAfter(), cert, nonce, sess, replyStatus, disabled, null), entry.getPrivate());
        }
        replies.add(reply);
        return reply;
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private void stall(HttpExchange exchange, SilentPeer.Stall stall) throws IOException {
        if (stall == SilentPeer.Stall.AFTER_HEADERS) {
            exchange.sendResponseHeaders(200, 100);
            exchange.getResponseBody().write("{\"o".getBytes(StandardCharsets.UTF_8));
            exchange.getResponseBody().flush();
        }
        try {
            closed.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Stops answering, and lets go of any call it is stalling; a second close does nothing. */
    @Override
    public synchronized void close() {
        if (executor.isShutdown()) {
            return;
        }
        closed.countDown();
        server.stop(0);
        executor.shutdownNow();
    }
}
