// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The bean that publishes this service's verification events: one for each request that fails verification under
 * {@code audit} or {@code enforce}. It exists only where {@code paztport.verify=true}; a service that verifies only to
 * decide attestation reports nothing, and nor does a partner's entry. Each event is logged as a
 * {@code PAZTPORT_EVENT} line; where {@code paztport.responder-url} is set it is also signed with the key at
 * {@code paztport.event-key-path}, which must then be set too, and posted to the responder.
 */
package org.paztport.spring.event;
