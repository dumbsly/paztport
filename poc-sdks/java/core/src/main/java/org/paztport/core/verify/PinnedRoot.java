// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.Objects;

/**
 * A signed root a verifier pins, already verified against its policy key: the root's bytes, its {@code rootId} and
 * its {@code notAfter}, current as a {@link PinnedKeyring} is. Roots that share a {@code rootId} are renewals of one
 * tree, so a proof naming that id may prove against any current one of them. The bytes are copied in and out, so
 * no caller changes what a verifier holds.
 */
public record PinnedRoot(byte[] root, String rootId, long notAfter) {

    public PinnedRoot {
        root = Objects.requireNonNull(root, "root").clone();
        Objects.requireNonNull(rootId, "rootId");
    }

    @Override
    public byte[] root() {
        return root.clone();
    }
}
