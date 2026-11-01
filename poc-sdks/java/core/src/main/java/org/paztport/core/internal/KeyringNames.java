// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.util.Map;
import org.paztport.core.policy.Routes;

/** The one reader check of the names a keyring lists its services by, wherever the keyring is read. */
public final class KeyringNames {

    private KeyringNames() {
    }

    /**
     * Refuses a keyring (the {@code services} of a file, a request's {@code clientKeyring}, a reply's
     * {@code serverKeyring}) that names a service by something that is not a route node. A name is data, so the
     * refusal names the member, not the name.
     */
    public static void requireRouteNodes(Map<String, String> keyring, String member) {
        for (String name : keyring.keySet()) {
            try {
                Routes.requireValidNode(name);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("member " + member + " holds a name that is not a route node");
            }
        }
    }
}
