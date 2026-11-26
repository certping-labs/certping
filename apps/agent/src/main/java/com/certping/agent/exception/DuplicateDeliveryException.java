// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

/**
 * A second delivery of an attempt that another delivery is already carrying (its order is recorded) or that already
 * ended. The listener settles it and does nothing else: no error is reported and the attempt's record is left as it
 * is, so the other delivery's order is still collected.
 */
public class DuplicateDeliveryException extends AgentException {

    public static final String CODE = "DUPLICATE_DELIVERY";

    public DuplicateDeliveryException(String message) {
        super(CODE, message);
    }
}
