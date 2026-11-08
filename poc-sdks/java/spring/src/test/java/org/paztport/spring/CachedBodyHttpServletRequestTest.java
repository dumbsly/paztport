// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * A POST form body the filter has read is served as parameters from the cached bytes, after the container's own
 * (query) parameters, in the order and with the decoding the container would use.
 */
class CachedBodyHttpServletRequestTest {

    private static final String FORM = "application/x-www-form-urlencoded";

    private static CachedBodyHttpServletRequest cached(MockHttpServletRequest container, String body) {
        return new CachedBodyHttpServletRequest(container, body.getBytes(StandardCharsets.UTF_8));
    }

    private static MockHttpServletRequest container(String method, String contentType) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/echo");
        request.setContentType(contentType);
        return request;
    }

    @Test
    void postFormFieldsAreParameters() {
        CachedBodyHttpServletRequest request = cached(container("POST", FORM), "field=hello");
        assertThat(request.getParameter("field")).isEqualTo("hello");
    }

    @Test
    void queryValuesComeFirst() {
        MockHttpServletRequest container = container("POST", FORM);
        container.setParameter("a", "q");
        CachedBodyHttpServletRequest request = cached(container, "a=b&a=c");
        assertThat(request.getParameterValues("a")).containsExactly("q", "b", "c");
        assertThat(request.getParameter("a")).isEqualTo("q");
        assertThat(request.getParameterMap()).containsOnlyKeys("a");
        assertThat(request.getParameterMap().get("a")).containsExactly("q", "b", "c");
        assertThat(Collections.list(request.getParameterNames())).containsExactly("a");
    }

    @Test
    void formSyntax() {
        CachedBodyHttpServletRequest request = cached(container("POST", FORM), "x&=v&s=a+b&p=%41%26");
        assertThat(request.getParameter("x")).isEmpty();
        assertThat(request.getParameterMap()).containsOnlyKeys("x", "s", "p");
        assertThat(request.getParameter("s")).isEqualTo("a b");
        assertThat(request.getParameter("p")).isEqualTo("A&");
    }

    @Test
    void contentTypeWithCharsetCounts() {
        CachedBodyHttpServletRequest request =
                cached(container("POST", "Application/X-WWW-Form-Urlencoded; charset=UTF-8"), "field=hello");
        assertThat(request.getParameter("field")).isEqualTo("hello");
    }

    @Test
    void onlyPostFormsAreRead() {
        assertThat(cached(container("PUT", FORM), "field=hello").getParameter("field")).isNull();
        assertThat(cached(container("POST", "application/json"), "field=hello").getParameter("field")).isNull();
        assertThat(cached(container("POST", null), "field=hello").getParameter("field")).isNull();
    }

    @Test
    void decodesWithTheEncodingSetAtTheCall() throws Exception {
        CachedBodyHttpServletRequest request = cached(container("POST", FORM), "n=caf%C3%A9");
        assertThat(request.getParameter("n")).isEqualTo("cafÃ©");
        request.setCharacterEncoding("UTF-8");
        assertThat(request.getParameter("n")).isEqualTo("café");
    }

    @Test
    void queryOnlyViewHidesBodyFields() throws Exception {
        MockHttpServletRequest container = container("POST", FORM);
        container.setParameter("q", "1");
        CachedBodyHttpServletRequest request = cached(container, "field=hello");
        HttpServletRequest view = request.withQueryParametersOnly();
        assertThat(request.getParameter("field")).isEqualTo("hello");
        assertThat(view.getParameter("field")).isNull();
        assertThat(view.getParameter("q")).isEqualTo("1");
        assertThat(view.getParameterValues("field")).isNull();
        assertThat(view.getParameterMap()).containsOnlyKeys("q");
        assertThat(Collections.list(view.getParameterNames())).isEqualTo(List.of("q"));
        assertThat(view.getMethod()).isEqualTo("POST");
        assertThat(new String(view.getInputStream().readAllBytes(), StandardCharsets.UTF_8))
                .isEqualTo("field=hello");
    }

    @Test
    void unknownCharsetFallsBackToIso88591() {
        for (String label : new String[] {"bogus", "not a charset!"}) {
            CachedBodyHttpServletRequest request =
                    cached(container("POST", FORM + "; charset=" + label), "n=caf%C3%A9");
            assertThat(request.getParameter("n")).as(label).isEqualTo("caf\u00c3\u00a9");
        }
    }

    @Test
    void readerWithUnknownCharsetFallsBackToUtf8() throws Exception {
        CachedBodyHttpServletRequest request = cached(container("POST", "text/plain; charset=bogus"), "caf\u00e9");
        assertThat(request.getReader().readLine()).isEqualTo("caf\u00e9");
    }

    @Test
    void malformedEscapeDropsOnlyThatField() {
        CachedBodyHttpServletRequest request = cached(container("POST", FORM), "a=%zz&b=1");
        assertThat(request.getParameter("a")).isNull();
        assertThat(request.getParameter("b")).isEqualTo("1");
    }
}
