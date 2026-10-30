// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.nio.charset.StandardCharsets;
import org.paztport.core.verify.ReasonCode;

/**
 * An answer the SDK gives in place of a handler's: a refusal, or the session endpoint's reply. The body is JSON,
 * sent labelled {@code application/json}, with no parameters, and exactly as these bytes, so a framework writes it out and does not
 * serialise it again. Each read of {@link #json} is a copy, so no caller can change what another is sent.
 *
 * @param status the HTTP status
 * @param json the body: UTF-8 JSON text
 */
public record HttpAnswer(int status, byte[] json) {

    public HttpAnswer {
        json = json.clone();
    }

    @Override
    public byte[] json() {
        return json.clone();
    }

    /**
     * A refusal: {@code {"reason":"<code>"}} and nothing more. A refusal tells the caller what to do next; who is
     * suspected is for the operator and the responder, so it is carried by the event only, where there is one. The
     * suspect is usually the caller itself, and naming it in the answer would tip it off before the responder acts.
     * The code is a {@link ReasonCode} name, so the body needs no escaping.
     */
    public static HttpAnswer refusal(int status, ReasonCode reason) {
        return new HttpAnswer(status, ("{\"reason\":\"" + reason.name() + "\"}").getBytes(StandardCharsets.UTF_8));
    }
}
