// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

import java.util.List;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.NonceKeys;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.VerifyInput;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.RequestBinding;

/**
 * The receivers' form of {@link HttpWire}'s request verify input, which takes a chain that has already been read. It is
 * not user-facing: its nonce key comes from {@code parsed}, so a caller could pass one that disagrees with
 * {@code chain}. The public overload on {@link HttpWire} reads the chain itself and so cannot be misused that way.
 */
public final class VerifyInputs {

    private VerifyInputs() {
    }

    /**
     * {@link HttpWire#request(String, String, String, String, String, byte[], String, String, Peer)} for a receiver
     * that has already decoded the chain header to {@code chain} ({@link HttpWire#decodeChain}) and read that to
     * {@code parsed} ({@code Chains.parse(chain)}), so that it reads one request's chain once rather than again here
     * for the nonce key. The verifier still reads {@code chain} itself, as it must: it trusts no reading but its own.
     *
     * <p>Not for callers outside the SDK: the nonce key is taken from {@code parsed} without checking that it is the
     * reading of {@code chain}.
     *
     * @param blocksHeader the {@code X-Path-Extensions} header as received, or null when none came
     * @param keyValue the key value the receiver read from {@code target} for its keyed operation, which the nonce
     *     key then carries ({@code [rid, lastSvc, lastRcv, keyValue, "req"]}), or null for none
     */
    public static VerifyInput request(String chain, ParsedChain parsed, String proofHeader, String blocksHeader,
            String method, String target, byte[] body, String receiver, String keyValue, Peer peer) {
        return new VerifyInput(chain, expectedBind(method, target, body), HttpWire.decodeBlocks(blocksHeader),
                HttpWire.decodeProof(proofHeader), receiver, true, requestNonceKey(parsed, keyValue), peer);
    }

    /** The request's binding, or null when it has none: a method or target with a lone surrogate binds nothing. */
    private static String expectedBind(String method, String target, byte[] body) {
        try {
            return RequestBinding.compute(method, target, body);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The request's nonce key (spec verification.md, Freshness and replay): {@code ""} for a chain that does not
     * parse, which check 1 refuses before any key is looked at; null for a key value that no key can carry (a lone
     * surrogate), whose target has no binding either, so check 8 refuses the request first, and a null key fails
     * closed should it be reached.
     */
    private static String requestNonceKey(ParsedChain parsed, String keyValue) {
        if (!parsed.ok()) {
            return "";
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp last = stamps.get(stamps.size() - 1);
        String rid = stamps.get(0).rid();
        try {
            return keyValue == null ? NonceKeys.of(rid, last.svc(), last.rcv(), "req")
                    : NonceKeys.of(rid, last.svc(), last.rcv(), keyValue, "req");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
