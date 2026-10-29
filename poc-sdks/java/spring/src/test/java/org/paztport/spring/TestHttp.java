// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * The JDK HTTP clients the tests make for themselves, every wait bounded, so that a call nobody answers fails its
 * test within {@link #REQUEST_TIMEOUT} rather than hanging the whole run. A call here reaching a process other than
 * the test's own server once did exactly that: that process took the connection and never replied, and with no
 * timeout the test waited for ever.
 */
public final class TestHttp {

    /** Far beyond any call here, which take milliseconds, yet short enough that a stall fails rather than hangs. */
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private TestHttp() {
    }

    public static HttpClient newClient() {
        return HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build();
    }

    /** A RestClient builder over {@code http}, whose calls each wait for their answer no longer than the timeout. */
    static RestClient.Builder restClient(HttpClient http) {
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(REQUEST_TIMEOUT);
        return RestClient.builder().requestFactory(factory);
    }

    /** A request to {@code uri} that times out rather than wait for ever. */
    public static HttpRequest.Builder request(URI uri) {
        return HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT);
    }
}
