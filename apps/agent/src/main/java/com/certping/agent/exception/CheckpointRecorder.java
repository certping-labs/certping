// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import java.util.function.Predicate;

/**
 * Records how far an attempt has got next to its certificate, so a message delivered again resumes there instead of
 * ordering again: a CA flow records the order it is about to send before sending it, and the order it got back.
 */
public interface CheckpointRecorder {

    /** For a flow with no message behind it: nothing is recorded. */
    CheckpointRecorder NONE = new CheckpointRecorder() {
        @Override
        public void recordBeforeSending(IssuanceCheckpoint sending) {
        }

        @Override
        public void recordNotSent(IssuanceCheckpoint sending) {
        }

        @Override
        public void recordAnswered(IssuanceCheckpoint answered) {
        }

        @Override
        public OrderOwner recordedOwner(Predicate<IssuanceCheckpoint> mine) {
            return OrderOwner.THIS_DELIVERY;
        }
    };

    /**
     * Records the order about to be sent. The order must not be sent when this throws.
     *
     * @throws DuplicateDeliveryException when another delivery of the attempt already recorded an order, or the
     *                                    attempt already failed
     * @throws RuntimeException           when the order is not recorded
     */
    void recordBeforeSending(IssuanceCheckpoint sending);

    /**
     * The CA refused the order recorded before sending, so it was not placed: the record goes back to where the
     * delivery started, and a redelivery does not look for an order that does not exist. Best effort.
     */
    void recordNotSent(IssuanceCheckpoint sending);

    /** Records an order the CA answered. Best effort: the record written before sending finds the order again. */
    void recordAnswered(IssuanceCheckpoint answered);

    /** Whose the attempt's order is, as its record shows. */
    enum OrderOwner {
        /** This delivery's, or the record cannot tell: the order is tracked and reported as this delivery's. */
        THIS_DELIVERY,
        /** Another delivery of the same request: it recorded the order ({@code mine} rejects it) or stored its result. */
        ANOTHER_DELIVERY,
        /** No one's: the request failed, or a newer request for the certificate replaced the record. */
        NO_ONE
    }

    /** Whose the attempt's order is, as its record shows; {@link OrderOwner#THIS_DELIVERY} when it cannot tell. */
    OrderOwner recordedOwner(Predicate<IssuanceCheckpoint> mine);
}
