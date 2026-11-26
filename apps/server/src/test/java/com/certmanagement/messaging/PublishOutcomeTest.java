// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import org.junit.jupiter.api.Test;
import tools.jackson.core.exc.StreamReadException;

import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

class PublishOutcomeTest {

    @Test
    void aCommandThatCouldNotBeSerializedWasNotSent() {
        RuntimeException failure = new RuntimeException("Failed to serialize CERT_RENEWAL command",
                new StreamReadException(null, "bad"));

        assertThat(PublishOutcome.of(failure)).isEqualTo(PublishOutcome.NOT_SENT);
    }

    @Test
    void aCommandRejectedBeforeSendingWasNotSent() {
        assertThat(PublishOutcome.of(new IllegalArgumentException("organizationId must be set")))
                .isEqualTo(PublishOutcome.NOT_SENT);
    }

    @Test
    void aTimeoutOrAnUnclassifiedFailureMayHaveBeenSent() {
        assertThat(PublishOutcome.of(new IllegalStateException("send timed out", new TimeoutException())))
                .isEqualTo(PublishOutcome.UNKNOWN);
        assertThat(PublishOutcome.of(new RuntimeException("connection reset"))).isEqualTo(PublishOutcome.UNKNOWN);
        assertThat(PublishOutcome.of(new org.springframework.dao.DataAccessResourceFailureException("insert lost")))
                .isEqualTo(PublishOutcome.UNKNOWN);
    }
}
