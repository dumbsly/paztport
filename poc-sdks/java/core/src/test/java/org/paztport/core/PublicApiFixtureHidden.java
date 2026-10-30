// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/** A class no user outside this package can name, nor any class inside it: for {@code PublicApiTest}. */
final class PublicApiFixtureHidden {

    private PublicApiFixtureHidden() {
    }

    /** Public, but inside a class nobody can name. */
    public static final class Nested {
    }
}
