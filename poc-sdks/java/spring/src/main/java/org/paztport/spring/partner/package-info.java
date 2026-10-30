// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Calls between organisations: the egress's client bean, a {@code paztport-http} {@code BoundaryClient} built from
 * {@code paztport.boundary.*}, and the adapters of the partner's side, which answer the session handshake
 * ({@code PartnerSessionController}) and refuse what an unsafe session may not do ({@code PartnerGate}) over
 * {@code paztport-http}'s session registry. The partner's request filter is {@code org.paztport.spring.PartnerFilter},
 * beside the inbound filter it stands in for.
 */
package org.paztport.spring.partner;
