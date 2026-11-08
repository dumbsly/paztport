// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Payment's handlers, each recording that it ran and answering its own name, so a test can tell which one ran.
 * {@link Charges} serves the entrances {@code POST /charge} and {@code PUT /charge}, each of whose two operations a
 * query condition tells apart; the operation {@code pay} is served by either {@link PayJson} or {@link PayAnyMethod}.
 */
final class PaymentHandlers {

    /** The handlers that ran, by name, in order. */
    static final List<String> RAN = new CopyOnWriteArrayList<>();

    private PaymentHandlers() {
    }

    private static String ran(String name) {
        RAN.add(name);
        return name;
    }

    @RestController
    static class Charges {

        @PostMapping("/charge")
        String charge() {
            return ran("charge");
        }

        @PostMapping(path = "/charge", params = "mode=refund")
        String refund() {
            return ran("refund");
        }

        @PutMapping("/charge")
        String amend() {
            return ran("amend");
        }

        @PutMapping(path = "/charge", params = "mode=refund")
        String amendRefund() {
            return ran("amendRefund");
        }
    }

    /** {@code pay} for a JSON body only: a media type alone on its entrance tells no operations apart. */
    @RestController
    static class PayJson {

        @PostMapping(path = "/pay", consumes = "application/json")
        String pay() {
            return ran("pay");
        }
    }

    /**
     * {@code POST /charge} and {@code PUT /charge} served by one handler method that two beans inherit, which a
     * class-level {@code params} condition tells apart: {@link ChargeSide} is {@code charge} and {@code amend}, and
     * {@link RefundSide} is {@code refund} and {@code amendRefund}. Each answers its own side's name.
     */
    abstract static class ChargeBase {

        @PostMapping("/charge")
        String post() {
            return ran(side());
        }

        @PutMapping("/charge")
        String put() {
            return ran(side());
        }

        abstract String side();
    }

    @RestController
    static class ChargeSide extends ChargeBase {

        @Override
        String side() {
            return "charge side";
        }
    }

    @RestController
    @RequestMapping(params = "mode=refund")
    static class RefundSide extends ChargeBase {

        @Override
        String side() {
            return "refund side";
        }
    }

    /** {@code pay} mapped on {@code POST /pay} by one handler method that two beans inherit. */
    abstract static class PayBase {

        @PostMapping("/pay")
        String pay() {
            return ran("pay");
        }
    }

    /** {@code pay} for a JSON body, which only its class-level media type tells apart from {@link PayTextSide}. */
    @RestController
    @RequestMapping(consumes = "application/json")
    static class PayJsonSide extends PayBase {
    }

    /** {@code pay} for a text body, which only its class-level media type tells apart from {@link PayJsonSide}. */
    @RestController
    @RequestMapping(consumes = "text/plain")
    static class PayTextSide extends PayBase {
    }

    /** {@code pay} mapped with no method, so for every method, the table's {@code POST} included. */
    @RestController
    static class PayAnyMethod {

        @RequestMapping("/pay")
        String pay() {
            return ran("pay");
        }
    }
}
