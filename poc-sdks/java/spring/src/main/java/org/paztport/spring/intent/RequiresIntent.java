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
 * <p>Only a request-mapping handler method, one a {@code @RequestMapping} annotation or its shortcuts such as
 * {@code @PostMapping} map, can carry it: {@link IntentCheck} sees no other handler, so on any other method of a bean,
 * a helper the handler calls or a method a router function refers to, nothing would check it. A service with an
 * annotated handler acts on {@code intent} ({@code paztport.extensions.acts-on}), and each name is a fact name: 1 to
 * 32 of {@code a} to {@code z}, {@code 0} to {@code 9} and {@code -}. Otherwise, or where the annotation is on a
 * method that is not a request-mapping handler, the context does not start ({@link IntentConfiguration}). A bean that
 * is created lazily or per request is looked at by the type its definition declares, so an annotation on a method
 * that type does not show is not found at the start.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresIntent {

    /** The names of the facts the handler requires; at least one. */
    String[] value();
}
