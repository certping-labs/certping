// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import java.time.Duration;

/**
 * The CA holds an order that is placed and validated but not issued yet. The worker lets the message go and the
 * listener brings it back after {@link #getRetryAfter()} to collect the order; nothing has failed.
 */
public class CaOrderPendingException extends RetryableAgentException {

    public static final String CODE = "CA_ORDER_PENDING";

    private final String provider;
    private final String orderRef;

    public CaOrderPendingException(String provider, String orderRef, Duration nextCheck, IssuanceCheckpoint checkpoint) {
        super(CODE, provider + " order " + orderRef + " is not issued yet; next check in " + nextCheck.toSeconds() + " s",
                nextCheck, null, checkpoint);
        this.provider = provider;
        this.orderRef = orderRef;
    }

    public String getProvider() {
        return provider;
    }

    public String getOrderRef() {
        return orderRef;
    }

    @Override
    public RetryableAgentException withCheckpoint(IssuanceCheckpoint checkpoint) {
        return new CaOrderPendingException(provider, orderRef, getRetryAfter(), checkpoint);
    }
}
