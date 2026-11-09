// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.boundary;

import java.util.List;
import org.paztport.core.influence.InfluenceEntry;

/**
 * Told what the egress is about to send a partner, so this organisation can keep what the blinded entries stood for.
 * The partner holds only one entry per class and owner, each a salted commitment; to open one later this
 * organisation needs the originals, which this is the only place to see, and
 * {@code BoundaryClient.opening} re-derives the salt.
 *
 * <p>It is called only in an attested session, after the request's chain passed the live order at this hop and
 * the session is open, and before the request is sent. An unsafe session sends no influence, so it is not called
 * there. An exception it throws stops the call before anything of the request is sent (the handshake may already
 * have happened) and reaches the caller of {@code BoundaryClient.post}: an entry this organisation could not record is
 * an entry it could never open, so it is not sent.
 *
 * <p>It may be called from several request threads at once, one call per request, so an implementation must be
 * thread-safe.
 *
 * <p>The originals are secrets of this organisation: internal service names and plain content hashes. Keep them where
 * it keeps its evidence, and never log them.
 */
@FunctionalInterface
public interface BoundaryListener {

    /**
     * @param rid the request's rid, from the chain verified at this hop
     * @param partnerEntry the partner's entry service, the boundary stamp's receiver
     * @param originals the request context's influence, normalised, every field kept; unmodifiable
     * @param sent exactly the list the boundary stamp commits to and the call carries; unmodifiable
     */
    void sent(String rid, String partnerEntry, List<InfluenceEntry> originals, List<InfluenceEntry> sent);
}
