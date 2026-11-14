// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

import java.util.Objects;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.Verifier;

/**
 * Where a builder's extension settings come from, the one rule for every builder that may hold a verifier: a service
 * states its settings once, so it cannot verify under one {@code actsOn} and build its blocks, or read what it is
 * handed, under another. It holds no state and is not for an application to use.
 */
public final class Extensions {

    private Extensions() {
    }

    /**
     * The verifier's settings where there is a verifier, otherwise those given, otherwise
     * {@link ExtensionSettings#NONE}.
     *
     * @param verifier the builder's verifier, or null for none
     * @param given the settings the builder was given, or null for none
     * @throws IllegalArgumentException when both are given and the settings differ from the verifier's
     */
    public static ExtensionSettings resolve(Verifier verifier, ExtensionSettings given) {
        if (verifier == null) {
            return given == null ? ExtensionSettings.NONE : given;
        }
        ExtensionSettings own = verifier.extensions();
        if (given != null && !(own.actsOn().equals(given.actsOn()) && Objects.equals(own.allowed(), given.allowed()))) {
            throw new IllegalArgumentException("the extension settings differ from the verifier's: a service states"
                    + " them once, in its verifier, or here when it has none");
        }
        return own;
    }
}
