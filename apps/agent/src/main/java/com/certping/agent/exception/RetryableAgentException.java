// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import lombok.Getter;

import java.time.Duration;

/**
 * Thrown for recoverable errors that should be re-scheduled on the agent's inbound queue
 * (with a {@code ScheduledEnqueueTime}) rather than abandoned for near-immediate redelivery.
 *
 * <p>Sibling of {@link TransientAgentException}. The distinction the listener acts on is
 * {@link #getRetryAfter()}:
 * <ul>
 *   <li><b>non-null</b> — upstream told us exactly how long to wait (an ACME {@code Retry-After},
 *       a provider {@code 429}/{@code ThrottlingException} hint). The listener honors it,
 *       capped, via a scheduled re-enqueue.</li>
 *   <li><b>null</b> — "retry, but we don't know when". The listener applies its blind backoff
 *       curve indexed by the message's {@code RetryCount} (same outcome as a
 *       {@link TransientAgentException}, but on a schedule instead of {@code abandon()}).</li>
 * </ul>
 *
 * <p>The key difference from {@link TransientAgentException} is that this never blocks the worker
 * thread on the wait: the <em>message</em> waits (scheduled on the queue), not the consumer.
 */
@Getter
public class RetryableAgentException extends AgentException {

    /** Exact wait requested by upstream, or {@code null} when we must back off blindly. */
    private final Duration retryAfter;

    /** Resume hint to stamp on the re-enqueued message. Null when nothing to checkpoint. */
    private final IssuanceCheckpoint checkpoint;

    public RetryableAgentException(String errorCode, String message) {
        this(errorCode, message, null, null, null);
    }

    public RetryableAgentException(String errorCode, String message, Duration retryAfter) {
        this(errorCode, message, retryAfter, null, null);
    }

    public RetryableAgentException(String errorCode, String message, Duration retryAfter, Throwable cause) {
        this(errorCode, message, retryAfter, cause, null);
    }

    public RetryableAgentException(String errorCode, String message, Duration retryAfter,
                                   Throwable cause, IssuanceCheckpoint checkpoint) {
        super(errorCode, message, cause);
        this.retryAfter = retryAfter;
        this.checkpoint = checkpoint;
    }

    /** Returns a copy of this exception with {@code checkpoint} attached. The original
     *  exception object is unchanged so callers that don't know about checkpoints (legacy
     *  classifier helpers) keep working unchanged. */
    public RetryableAgentException withCheckpoint(IssuanceCheckpoint checkpoint) {
        return new RetryableAgentException(getErrorCode(), getMessage(), retryAfter, getCause(), checkpoint);
    }
}
