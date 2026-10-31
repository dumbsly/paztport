// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Text;

/**
 * The two hash operations of the tree, with mandatory domain separation:
 * leaves are prefixed {@code 0x00}, internal nodes {@code 0x01}. Without this a
 * leaf could be reinterpreted as an internal node (a second-preimage attack).
 */
public final class MerkleHash {

    private static final byte LEAF = 0x00;
    private static final byte NODE = 0x01;

    private MerkleHash() {
    }

    /**
     * {@code SHA-256(0x00 || salt || path)}. A path with a lone surrogate has no UTF-8 form, and encoding it would
     * turn it into {@code ?}, so it is refused with {@link IllegalArgumentException}.
     */
    public static byte[] leaf(byte[] salt, String path) {
        if (!Text.isWellFormed(path)) {
            throw new IllegalArgumentException("leaf: not well-formed Unicode");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(LEAF);
        out.write(salt, 0, salt.length);
        byte[] p = path.getBytes(StandardCharsets.UTF_8);
        out.write(p, 0, p.length);
        return Crypto.sha256(out.toByteArray());
    }

    /** {@code SHA-256(0x01 || left || right)}. */
    public static byte[] node(byte[] left, byte[] right) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(NODE);
        out.write(left, 0, left.length);
        out.write(right, 0, right.length);
        return Crypto.sha256(out.toByteArray());
    }
}
