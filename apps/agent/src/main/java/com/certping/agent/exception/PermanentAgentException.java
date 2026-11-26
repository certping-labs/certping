// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

/**
 * Thrown for unrecoverable errors (bad payload, invalid KV path, auth failures).
 * The listener will publish AGENT_ERROR and call context.deadLetter().
 */
public class PermanentAgentException extends AgentException {

    public PermanentAgentException(String errorCode, String message) {
        super(errorCode, message);
    }

    public PermanentAgentException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
