// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * One hop's stamp. Pure data plus its canonical signing form.
 *
 * <p>{@code sig} signs the canonical bytes {@code svc|inst|rid|ts|bind|prev}.
 * {@code prev} is the base64url signature of the previous stamp, empty for the
 * origin. {@code bind} covers the outbound request this hop sent. Every field
 * is required: a stamp with a missing one is malformed, not a stamp of empty
 * values.
 */
public record Stamp(
        String svc,
        String inst,
        String rid,
        long ts,
        String bind,
        String prev,
        String sig) {

    public Stamp {
        Objects.requireNonNull(svc, "svc");
        Objects.requireNonNull(inst, "inst");
        Objects.requireNonNull(rid, "rid");
        Objects.requireNonNull(bind, "bind");
        Objects.requireNonNull(prev, "prev");
        Objects.requireNonNull(sig, "sig");
    }

    /** The exact bytes covered by {@link #sig()}. */
    public byte[] signingBytes() {
        return (svc + "|" + inst + "|" + rid + "|" + ts + "|" + bind + "|" + prev)
                .getBytes(StandardCharsets.UTF_8);
    }
}
