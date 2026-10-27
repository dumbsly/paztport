// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/** The four classes of content that can influence an agent, with the names they carry on the wire. */
public enum InfluenceClass {
    THIRD_PARTY("third-party"),
    PRIVATE("private"),
    PUBLIC("public"),
    LOCAL_UNTRUSTED("local-untrusted");

    private final String wire;

    InfluenceClass(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }

    /** The class for a wire name, or null when the name is unknown (the caller decides how to fail). */
    public static InfluenceClass fromWire(String name) {
        for (InfluenceClass c : values()) {
            if (c.wire.equals(name)) {
                return c;
            }
        }
        return null;
    }
}
