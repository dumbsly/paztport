// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

import java.util.List;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.http.wire.HttpV3;
import org.paztport.http.wire.RequestBinding;

/**
 * The receivers' form of {@link HttpV3}'s request verify input, which takes a chain that has already been read. It is
 * not user-facing: its nonce key comes from {@code parsed}, so a caller could pass one that disagrees with
 * {@code chain}. The public overload on {@link HttpV3} reads the chain itself and so cannot be misused that way.
 */
public final class VerifyInputs {

    private VerifyInputs() {
    }

    /**
     * {@link HttpV3#request(String, String, String, String, String, byte[], String, Peer)} for a receiver that has
     * already decoded the chain header to {@code chain} ({@link HttpV3#decodeChain}) and read that to {@code parsed}
     * ({@code Chains.parse(chain)}), so that it reads one request's chain once rather than again here for the
     * nonce key. The verifier still reads {@code chain} itself, as it must: it trusts no reading but its own.
     *
     * <p>Not for callers outside the SDK: the nonce key is taken from {@code parsed} without checking that it is the
     * reading of {@code chain}.
     */
    public static VerifyInputV3 request(String chain, ParsedChain parsed, String proofHeader, String influenceHeader,
            String method, String target, byte[] body, String receiver, Peer peer) {
        return new VerifyInputV3(chain, expectedBind(method, target, body),
                HttpV3.decodeInfluence(influenceHeader), HttpV3.decodeProof(proofHeader), receiver, true,
                requestNonceKey(parsed), peer);
    }

    /** The request's binding, or null when it has none: a method or target with a lone surrogate binds nothing. */
    private static String expectedBind(String method, String target, byte[] body) {
        try {
            return RequestBinding.compute(method, target, body);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String requestNonceKey(ParsedChain parsed) {
        if (!parsed.ok()) {
            return "";
        }
        List<StampV3> stamps = parsed.stamps();
        return stamps.get(0).rid() + "|" + stamps.get(stamps.size() - 1).svc() + "|req";
    }
}
