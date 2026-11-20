// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.intent;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The facts a handler method requires of the request's origin (spec intent.md, How a receiver knows a fact is
 * required), on the handler that compares them, so the requirement and the comparison change together. Before the
 * handler runs, {@link IntentCheck} refuses a request whose verified origin did not state each of them
 * {@code 403 INTENT_MISSING}, and one served without verifying the same way, in every mode. The handler then reads
 * the facts from {@link org.paztport.http.OriginIntent#facts}, compares them with its request, and answers a
 * difference {@code 403 INTENT_DENIED} ({@link org.paztport.http.OriginIntent#deny}).
 *
 * <p>A service with an annotated handler acts on {@code intent} ({@code paztport.extensions.acts-on}), and each name
 * is a fact name: 1 to 32 of {@code a} to {@code z}, {@code 0} to {@code 9} and {@code -}. Otherwise the context does
 * not start ({@link IntentConfiguration}).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresIntent {

    /** The names of the facts the handler requires; at least one. */
    String[] value();
}
