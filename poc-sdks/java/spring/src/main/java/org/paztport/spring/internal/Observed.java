// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import io.micrometer.observation.Observation;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Runs a step as one started observation: the observation is open while the step runs and stopped before
 * {@link #run} returns. The starter's filters and interceptor share it, so each handles a throwing observation
 * handler the same way. It is not for an application to use.
 *
 * <p>If the step throws, the exception is recorded on the observation and goes on. If an observation handler throws
 * as it records that exception, or as it stops while that exception, or its scope's, is going on, the handler's
 * exception is added to it as suppressed, so the first exception is the one that goes on. If a handler throws once
 * the step has finished, as its scope closes or as it stops, whatever the step {@linkplain Body#call held} is
 * released before that exception goes on.
 */
public final class Observed {

    /** The step: it returns its result, and may hand over a resource to release if anything later fails. */
    @FunctionalInterface
    public interface Body<T, X extends Throwable> {

        /**
         * Runs the step.
         *
         * @param hold called with a resource as soon as the step has it; it is released if this step, or the
         *     observation around it, then fails
         */
        T call(Consumer<T> hold) throws X;
    }

    private Observed() {
    }

    /**
     * Runs {@code body} inside {@code observation}, which is already started.
     *
     * @param tags applied to the observation just before it stops, with the step's result, or null where the step
     *     did not finish
     * @param release called with what the step held, if it held anything, when the step or the observation fails
     * @return the step's result
     */
    public static <T, X extends Throwable> T run(Observation observation, Body<T, X> body,
            BiConsumer<Observation, T> tags, Consumer<T> release) throws X {
        Holder<T> held = new Holder<>();
        T result = null;
        Throwable failure = null;
        try {
            try (Observation.Scope open = observation.openScope()) {
                result = body.call(value -> held.value = value);
            } catch (Throwable t) {
                failure = t;
                try {
                    observation.error(t);
                } catch (Throwable erroring) {
                    if (erroring != t) {
                        t.addSuppressed(erroring);
                    }
                }
                throw t;
            } finally {
                try {
                    tags.accept(observation, result);
                    observation.stop();
                } catch (Throwable stopping) {
                    if (failure == null) {
                        throw stopping;
                    }
                    if (stopping != failure) {
                        failure.addSuppressed(stopping);
                    }
                }
            }
            return result;
        } catch (Throwable t) {
            if (held.value != null) {
                release.accept(held.value);
            }
            throw t;
        }
    }

    private static final class Holder<T> {
        private T value;
    }
}
