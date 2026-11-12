// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;
import org.paztport.spring.outbound.UnconnectedRetry.Failure;

/** Which failures count as never connected, and when a retry could no longer arrive in time. */
class UnconnectedRetryTest {

    /** A connect timeout as the JDK's client gives it: with the {@code ConnectException} it ended as its cause. */
    private static HttpConnectTimeoutException connectTimeout() {
        HttpConnectTimeoutException e = new HttpConnectTimeoutException("HTTP connect timed out");
        e.initCause(new ConnectException("HTTP connect timed out"));
        return e;
    }

    @Test
    void classifiesTheThreeFailuresBeforeTheConnection() {
        assertEquals(Optional.of(Failure.CONNECT_TIMEOUT), UnconnectedRetry.classify(connectTimeout()));
        assertEquals(Optional.of(Failure.CONNECT), UnconnectedRetry.classify(new ConnectException("refused")));
        assertEquals(Optional.of(Failure.HANDSHAKE),
                UnconnectedRetry.classify(new SSLHandshakeException("Remote host terminated the handshake")));
    }

    @Test
    void classifiesThemWrapped() {
        assertEquals(Optional.of(Failure.CONNECT_TIMEOUT),
                UnconnectedRetry.classify(new IOException("wrapped", connectTimeout())));
        assertEquals(Optional.of(Failure.CONNECT),
                UnconnectedRetry.classify(new IOException("wrapped", new ConnectException("refused"))));
        assertEquals(Optional.of(Failure.HANDSHAKE),
                UnconnectedRetry.classify(new IOException("wrapped", new SSLHandshakeException("bad"))));
    }

    @Test
    void classifiesNothingThatMayHaveReachedTheReceiver() {
        for (Throwable t : List.of(new HttpTimeoutException("request timed out"),
                new IOException("HTTP/1.1 header parser received no bytes"), new ClosedChannelException(),
                new SocketException("Connection reset"))) {
            assertEquals(Optional.empty(), UnconnectedRetry.classify(t), t.toString());
        }
    }

    /**
     * The JDK's connect timer can fire after the TLS handshake has completed, as the request is being written: the
     * client then reports a request timeout, since the connection was established, with the timer's
     * {@code ConnectException} as its cause, and the request may have reached the receiver.
     */
    @Test
    void aRequestTimeoutIsNotAConnectFailureWhateverItsCause() {
        HttpTimeoutException timedOut = new HttpTimeoutException("request timed out");
        timedOut.initCause(new ConnectException("HTTP connect timed out"));

        assertEquals(Optional.empty(), UnconnectedRetry.classify(timedOut));
        assertEquals(Optional.empty(), UnconnectedRetry.classify(new IOException("wrapped", timedOut)));
    }

    @Test
    void theFirstOfTheClientsFailuresDecidesNotOneOfItsCauses() {
        assertEquals(Optional.empty(), UnconnectedRetry.classify(
                new SSLException("closed after the request was written", new SSLHandshakeException("bad"))));
        assertEquals(Optional.empty(), UnconnectedRetry.classify(
                new SSLException("closed after the request was written", new ConnectException("refused"))));
        assertEquals(Optional.of(Failure.CONNECT_TIMEOUT), UnconnectedRetry.classify(
                new IOException("wrapped", new IOException("wrapped again", connectTimeout()))));
    }

    @Test
    void endsOnACauseChainThatLoops() {
        IOException a = new IOException("a");
        IOException b = new IOException("b", a);
        a.initCause(b);

        assertEquals(Optional.empty(), UnconnectedRetry.classify(a));
    }

    @Test
    void aRetryIsHopelessOnceTheOriginStampCouldNotArriveInTime() {
        UnconnectedRetry retry = new UnconnectedRetry(Duration.ofMillis(1000), 5000,
                Clock.fixed(Instant.ofEpochMilli(10_000), ZoneOffset.UTC));

        assertFalse(retry.hopeless(null), "with no origin stamp to age, the retry's stamp is the origin's");
        assertFalse(retry.hopeless(10_000L - 3999), "3999 ms old plus a 1000 ms connect is inside 5000 ms");
        assertTrue(retry.hopeless(10_000L - 4000), "4000 ms old plus a 1000 ms connect reaches 5000 ms");
    }
}
