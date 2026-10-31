// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

/**
 * JSON that Paztport does not read or write, with the {@link Step} that refused it. A reader takes bytes in the
 * steps the spec's JSON section gives (size, parse, canonical bytes), and a caller that checks an object's schema
 * next can tell bytes that never read from a well-formed object it refuses. The message names the rule broken and
 * where, never the refused text.
 */
public final class MalformedJsonException extends IllegalArgumentException {

    /** Where JSON was refused. */
    public enum Step {
        /** The bytes, or a token's text, are past their limit, checked before anything is parsed. */
        SIZE,
        /** The bytes are not one JSON value under the spec's grammar, within the depth limit. */
        PARSE,
        /** Wire bytes that read but are not the canonical bytes of what they hold. */
        CANONICAL,
        /** A value a writer refuses, since no reader would read it. */
        WRITE
    }

    private final Step step;

    public MalformedJsonException(Step step, String message) {
        super(message);
        this.step = step;
    }

    public Step step() {
        return step;
    }
}
