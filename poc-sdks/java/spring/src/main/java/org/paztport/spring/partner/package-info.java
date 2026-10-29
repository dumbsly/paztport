// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Calls between organisations: the egress's client to a partner, and the partner's side, which answers the session
 * handshake, keeps the sessions it opened and refuses what an unsafe one may not do. The partner's request filter is
 * {@code org.paztport.spring.PartnerFilter}, kept at the root because only the filters there may mark a chain verified.
 */
package org.paztport.spring.partner;
