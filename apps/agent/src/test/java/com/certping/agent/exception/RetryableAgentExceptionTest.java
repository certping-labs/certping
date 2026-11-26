// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RetryableAgentExceptionTest {

    @Test
    void carriesErrorCodeMessageAndRetryAfter() {
        Duration retryAfter = Duration.ofHours(2);
        RetryableAgentException ex =
                new RetryableAgentException("ACME_RATE_LIMITED", "rate limited", retryAfter);

        assertThat(ex.getErrorCode()).isEqualTo("ACME_RATE_LIMITED");
        assertThat(ex.getMessage()).isEqualTo("rate limited");
        assertThat(ex.getRetryAfter()).isEqualTo(retryAfter);
    }

    @Test
    void retryAfterIsNullForBlindRetry() {
        RetryableAgentException ex = new RetryableAgentException("CODE", "blip");

        assertThat(ex.getRetryAfter()).isNull();
        assertThat(ex.getCause()).isNull();
    }

    @Test
    void preservesCause_andIsAnAgentException() {
        RuntimeException cause = new RuntimeException("boom");
        RetryableAgentException ex =
                new RetryableAgentException("CODE", "msg", Duration.ofSeconds(30), cause);

        assertThat(ex.getCause()).isSameAs(cause);
        assertThat(ex).isInstanceOf(AgentException.class);
    }

    @Test
    void fullConstructor_carriesCheckpoint() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint(
                "LE", IssuanceCheckpoint.Step.ORDER_CREATED, "ref", "acct", "kv");
        RuntimeException cause = new RuntimeException("boom");
        RetryableAgentException ex = new RetryableAgentException(
                "CODE", "msg", Duration.ofSeconds(10), cause, cp);

        assertThat(ex.getCheckpoint()).isSameAs(cp);
        assertThat(ex.getCause()).isSameAs(cause);
        assertThat(ex.getRetryAfter()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void withCheckpoint_returnsNewInstanceWithCheckpointAndSameOtherFields() {
        RuntimeException cause = new RuntimeException("boom");
        RetryableAgentException original = new RetryableAgentException(
                "CODE", "msg", Duration.ofSeconds(30), cause);

        IssuanceCheckpoint cp = new IssuanceCheckpoint(
                "LE", IssuanceCheckpoint.Step.ORDER_CREATED, "ref", "acct", "kv");
        RetryableAgentException copy = original.withCheckpoint(cp);

        assertThat(copy).isNotSameAs(original);
        assertThat(copy.getErrorCode()).isEqualTo("CODE");
        assertThat(copy.getMessage()).isEqualTo("msg");
        assertThat(copy.getRetryAfter()).isEqualTo(Duration.ofSeconds(30));
        assertThat(copy.getCause()).isSameAs(cause);
        assertThat(copy.getCheckpoint()).isSameAs(cp);
        // Original unchanged
        assertThat(original.getCheckpoint()).isNull();
    }

    @Test
    void twoArgConstructor_defaultsRetryAfterAndCheckpointToNull() {
        RetryableAgentException ex = new RetryableAgentException("CODE", "blip");
        assertThat(ex.getRetryAfter()).isNull();
        assertThat(ex.getCheckpoint()).isNull();
        assertThat(ex.getCause()).isNull();
    }

    @Test
    void threeArgConstructor_carriesRetryAfterOnly() {
        RetryableAgentException ex = new RetryableAgentException(
                "CODE", "msg", Duration.ofMinutes(2));
        assertThat(ex.getRetryAfter()).isEqualTo(Duration.ofMinutes(2));
        assertThat(ex.getCheckpoint()).isNull();
        assertThat(ex.getCause()).isNull();
    }
}
