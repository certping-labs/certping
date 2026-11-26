// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

/** Meters the listener records for retryable failures, named here so the code that alerts on them can find them. */
public final class RetryMetrics {

    /** Counted per {@code messageType} and {@code reasonCode} when a message's retries run out. */
    public static final String GIVE_UP = "agent.message.retry.giveup.count";

    private RetryMetrics() {
    }
}
