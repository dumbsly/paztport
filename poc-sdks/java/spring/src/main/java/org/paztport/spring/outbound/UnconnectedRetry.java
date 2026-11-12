// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.http.HttpConnectTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import javax.net.ssl.SSLHandshakeException;

/**
 * What {@link OutboundInterceptor} needs to decide whether to retry a call that failed before its connection was
 * established: which failures those are, and whether a retry could still arrive inside its receiver's window.
 *
 * <p>The failures are exactly three, told apart by type: the connect timed out ({@link HttpConnectTimeoutException}),
 * the connect was refused ({@link ConnectException}, which the JDK's client has already retried once itself), or the
 * TLS handshake failed ({@link SSLHandshakeException}, including a peer that closes or resets the connection part way
 * through it). The JDK's client writes no byte of a request until the TCP connect and the TLS handshake have both
 * completed, and sends no TLS early data, so a call that failed in one of these ways never reached its receiver.
 * Nothing else is matched: a pooled connection the peer has closed, a reset after the request was written and a read
 * timeout ({@code HttpTimeoutException} that is not a connect timeout) may each have reached the receiver.
 *
 * <p>Only calls whose method is neither {@code GET} nor {@code HEAD} are covered ({@link #covers}). The JDK's client
 * re-sends a {@code GET} or {@code HEAD} itself when the connection it was written on dies before the response, and if
 * that re-send's connect fails, the call fails with a connect failure that keeps no trace of the first attempt, which
 * may have been delivered. Those two methods stay under the JDK's own handling. Under the JDK's net property
 * {@value #JDK_ALL_METHOD_RETRY} the JDK re-sends every method that way, so the starter does not retry at all there
 * ({@link #jdkRetriesEveryMethod}).
 *
 * @param connectTimeout how long the retry's connect may take, {@code paztport.connect-timeout-ms}
 * @param originWindowMs how old the origin's stamp may be when it arrives, the effective
 *     {@code paztport.run-max-age-ms}: this service's own setting, standing in for its receiver's, which it cannot know
 * @param clock what the origin stamp's age is measured against
 */
public record UnconnectedRetry(Duration connectTimeout, long originWindowMs, Clock clock) {

    /** The JDK client's net property under which it re-sends a request of any method after its connection dies. */
    public static final String JDK_ALL_METHOD_RETRY = "jdk.httpclient.enableAllMethodRetry";

    /** How a call failed before its connection was established. */
    public enum Failure {
        /** The TCP connect, or the TLS handshake after it, did not complete within the connect timeout. */
        CONNECT_TIMEOUT("connect_timeout"),
        /** The TCP connect was refused, after the JDK's client had retried it once. */
        CONNECT("connect"),
        /** The TLS handshake failed or the peer closed the connection during it. */
        HANDSHAKE("handshake");

        private final String tag;

        Failure(String tag) {
            this.tag = tag;
        }

        /** The failure's name in the retry observation and trace line. */
        public String tag() {
            return tag;
        }
    }

    public UnconnectedRetry {
        Objects.requireNonNull(connectTimeout, "connectTimeout");
        Objects.requireNonNull(clock, "clock");
    }

    /**
     * Whether a call with {@code method} may be retried: any method but {@code GET} and {@code HEAD}, whose connect
     * failure may follow an attempt the JDK's client already sent and re-sent itself.
     */
    public static boolean covers(String method) {
        return !"GET".equals(method) && !"HEAD".equals(method);
    }

    /**
     * Whether the JDK client re-sends a request of every method, not only {@code GET} and {@code HEAD}, after the
     * connection it was written on dies: {@value #JDK_ALL_METHOD_RETRY} read as the JDK reads it, from the system
     * property, else from {@code ${java.home}/conf/net.properties}, and on when present and either empty or
     * {@code true} ({@link Boolean#parseBoolean}). A file that cannot be read counts as absent, as it does for the JDK.
     */
    public static boolean jdkRetriesEveryMethod() {
        String value = System.getProperty(JDK_ALL_METHOD_RETRY);
        if (value == null) {
            Path file = Path.of(System.getProperty("java.home"), "conf", "net.properties");
            Properties net = new Properties();
            try (InputStream in = Files.newInputStream(file)) {
                net.load(in);
            } catch (IOException | RuntimeException unreadable) {
                return false;
            }
            value = net.getProperty(JDK_ALL_METHOD_RETRY);
        }
        return value != null && (value.isEmpty() || Boolean.parseBoolean(value));
    }

    /**
     * Which of the three failures {@code t} is, looking at it and then at each of its causes in turn, since a client
     * may wrap the JDK's exception; empty when none of them is one. A connect timeout is told apart before a refused
     * connect, as the JDK gives it a {@link ConnectException} as its cause.
     */
    public static Optional<Failure> classify(Throwable t) {
        // A chain of causes can loop back on itself, so each one is looked at once.
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable c = t; c != null && seen.add(c); c = c.getCause()) {
            if (c instanceof HttpConnectTimeoutException) {
                return Optional.of(Failure.CONNECT_TIMEOUT);
            }
            if (c instanceof ConnectException) {
                return Optional.of(Failure.CONNECT);
            }
            if (c instanceof SSLHandshakeException) {
                return Optional.of(Failure.HANDSHAKE);
            }
        }
        return Optional.empty();
    }

    /**
     * Whether a retry could not arrive while the origin's stamp is still inside the window: true when the stamp's age
     * now, plus a whole connect timeout, has reached {@link #originWindowMs}. A retry is not freshly signed by the
     * origin, so re-stamping does not make the origin's stamp any younger. False when {@code originTs} is null, as
     * where this service is the origin or the call is made outside a request, since the retry's stamp is then the
     * origin's, signed afresh.
     */
    public boolean hopeless(Long originTs) {
        return originTs != null && clock.millis() - originTs + connectTimeout.toMillis() >= originWindowMs;
    }
}
