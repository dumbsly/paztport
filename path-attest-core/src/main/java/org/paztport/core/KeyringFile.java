// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Map;

/**
 * The on-disk {@code keyring.json}: every service's public key plus the policy
 * public key, each as a base64url X.509 string. Public material only. Produced
 * by keygen, read by every service and verifier.
 */
public record KeyringFile(Map<String, String> services, String policy) {

    public KeyringFile {
        services = Map.copyOf(services);
    }
}
