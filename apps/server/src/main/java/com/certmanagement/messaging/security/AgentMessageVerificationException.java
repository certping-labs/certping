// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.security;

/**
 * Raised when an agent message cannot be authenticated.
 *
 * <p>{@link #isPermanent()} separates the two cases the caller must settle differently. A message that
 * is not authentic (a body naming another organization) is permanent: redelivering it produces the same
 * verdict, so it is dead-lettered once. A check that could not be completed is not the sender's fault
 * and must be retried.
 */
public class AgentMessageVerificationException extends RuntimeException {

    private final String reason;
    private final boolean permanent;

    private AgentMessageVerificationException(String reason, String message, boolean permanent) {
        super(message);
        this.reason = reason;
        this.permanent = permanent;
    }

    /** The message is not authentic. Dead-letter it. */
    public static AgentMessageVerificationException rejected(String reason, String message) {
        return new AgentMessageVerificationException(reason, message, true);
    }

    /** Verification could not be completed. Retry it. */
    public static AgentMessageVerificationException unavailable(String reason, String message) {
        return new AgentMessageVerificationException(reason, message, false);
    }

    /** Short, bounded-cardinality reason code, safe for metrics and logs. */
    public String getReason() {
        return reason;
    }

    public boolean isPermanent() {
        return permanent;
    }
}
