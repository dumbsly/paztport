// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The operations a service names: its own operation table, against which the inbound filter confirms the operation
 * each request is dispatched to, and its receivers' tables, from which its calls name the operation they invoke,
 * each used only where the signed root covers it.
 */
package org.paztport.spring.operation;
