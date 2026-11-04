// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.observation;

import io.micrometer.common.docs.KeyName;
import io.micrometer.observation.docs.ObservationDocumentation;

/**
 * The observations this starter records, each the verification of one request or one response at this hop. A tag the
 * starter sets is only ever one of the fixed words or a reason code's name: nothing from the request, such as a
 * service name, a request id or a peer, is a tag, so the number of series stays small whatever traffic arrives. Where
 * what an observation spans throws, it is recorded with the error, which Micrometer's meter handler tags as
 * {@code error}, and with the values each observation below gives for a throw.
 */
public enum PaztportObservation implements ObservationDocumentation {

    /**
     * A request to a service of this organisation, in {@code InboundFilter}. It spans the decision and ends before
     * the handler runs. A decision that throws is recorded with a reason of {@code none} and an outcome of
     * {@code refused}.
     */
    REQUEST("paztport.request", Keys.MODE, Keys.REASON, Keys.OUTCOME),

    /**
     * A call from another organisation to this one's partner entry, in {@code PartnerFilter}. It spans the decision
     * and ends before the handler runs. A decision that throws is recorded with a session of {@code unknown}, a
     * reason of {@code none} and an outcome of {@code refused}.
     */
    PARTNER_REQUEST("paztport.partner.request", Keys.SESSION, Keys.REASON, Keys.OUTCOME),

    /**
     * The response to a call this service made, in {@code OutboundInterceptor}. It spans the response check and ends
     * before the interceptor returns. A check that throws is recorded with a reason of {@code none}.
     */
    RESPONSE("paztport.response", Keys.REASON);

    private final String name;
    private final KeyName[] lowCardinalityKeys;

    PaztportObservation(String name, KeyName... lowCardinalityKeys) {
        this.name = name;
        this.lowCardinalityKeys = lowCardinalityKeys;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public KeyName[] getLowCardinalityKeyNames() {
        return lowCardinalityKeys.clone();
    }

    /** The tag keys of the observations above. */
    public enum Keys implements KeyName {

        /**
         * How the filter verifies requests: {@code off}, {@code audit} or {@code enforce} where it verifies them
         * ({@code paztport.verify=true}), otherwise {@code none}.
         */
        MODE("mode"),

        /**
         * The name of the reason code the verification gave, or {@code none} where none ran or it was not
         * available.
         */
        REASON("reason"),

        /** Whether the request was {@code served} or {@code refused}. */
        OUTCOME("outcome"),

        /** The session a partner's call named: {@code attested}, {@code unsafe} or {@code unknown}. */
        SESSION("session");

        private final String key;

        Keys(String key) {
            this.key = key;
        }

        @Override
        public String asString() {
            return key;
        }
    }
}
