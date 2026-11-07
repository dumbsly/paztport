// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import java.util.List;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;

/**
 * The verifier the outbound interceptor checks responses with: the same pinned material as the {@link Verifier}
 * bean, over the starter's own in-memory nonce cache. An application's {@link NonceCache} bean reaches requests
 * only. A response stamp chains onto the stamp this replica sent, so only the replica that sent a call can check its
 * answer, and a shared store would have nothing to share; nor does a store that is down then fail a call the
 * downstream has already acted on. It is a type of its own so that the {@code Verifier} bean stays the only one of
 * its type.
 */
public final class ResponseVerifier {

    private final VerifierConfig material;
    private final List<SignedRoot> roots;
    private final Verifier verifier;

    ResponseVerifier(VerifierConfig material, List<SignedRoot> roots) {
        this.material = material;
        this.roots = List.copyOf(roots);
        this.verifier = new Verifier(material);
    }

    /** The verifier for responses. */
    public Verifier verifier() {
        return verifier;
    }

    /**
     * The signed roots pinned, this service's own first and then the overlap's, each verified under the policy pin
     * and current at startup: what else a root covers, such as an operation table, is checked against these.
     */
    public List<SignedRoot> roots() {
        return roots;
    }

    /** The pinned material, for the requests' verifier to take over another cache. */
    VerifierConfig material() {
        return material;
    }
}
