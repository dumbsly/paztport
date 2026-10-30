// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The one bound on a JDK client's exchange that every call the SDK makes shares: the Spring starter's pooled client
 * ({@code WholeExchangeRequestFactory}), the egress's calls to the partner and the events. It holds no state and is
 * not for an application to use.
 */
public final class WholeExchange {

    private WholeExchange() {
    }

    /**
     * Sends {@code request} on {@code http} and waits for the whole answer, its body included, for no longer than
     * the request's timeout, which it must have. Waiting here is what bounds the body on every JDK, since JDK 25
     * applies a request's timeout only to the wait for the headers (JDK 27 applies it to the body too, so there the
     * JDK's own timeout may end the call first). Past it the exchange is cancelled, which closes its connection, and
     * the call fails as an {@link HttpTimeoutException}.
     *
     * @throws IOException when the call fails, has no whole answer within the timeout, or the thread is
     *     interrupted (whose interrupt is kept)
     */
    public static <T> HttpResponse<T> send(HttpClient http, HttpRequest request, HttpResponse.BodyHandler<T> body)
            throws IOException {
        Duration timeout = request.timeout()
                .orElseThrow(() -> new IllegalArgumentException("the request must have a timeout"));
        CompletableFuture<HttpResponse<T>> answer = http.sendAsync(request, body);
        try {
            return answer.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            answer.cancel(true);
            throw new HttpTimeoutException("no whole answer within " + timeout.toMillis() + " ms");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw new IOException(e.getCause());
        } catch (InterruptedException e) {
            answer.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }
}
