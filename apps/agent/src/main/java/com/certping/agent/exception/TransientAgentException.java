// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

/**
 * Thrown for recoverable errors (network timeouts, rate limits, KV throttle).
 * The listener normally schedules the message for retry. A processor may convert it to a permanent
 * command failure when replaying that command would be unsafe, as device sync does after streamed
 * response parts may have escaped.
 */
public class TransientAgentException extends AgentException {

    public TransientAgentException(String errorCode, String message) {
        super(errorCode, message);
    }

    public TransientAgentException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
