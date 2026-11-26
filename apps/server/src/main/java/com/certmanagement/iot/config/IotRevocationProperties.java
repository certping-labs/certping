// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Data
@Component
@ConfigurationProperties(prefix = "certping.iot.revocation")
public class IotRevocationProperties {
    private int claimBatchSize = 100;
    private int maxDispatchAttempts = 8;
    private int publishConcurrency = 16;
    private Duration maxOperationAge = Duration.ofDays(7);
    private Duration claimLease = Duration.ofMinutes(15);
    /** Longer than the agent's jittered eight-step retry curve, avoiding duplicate retry trees. */
    private Duration responseTimeout = Duration.ofHours(76);
    /** Avoids hot-row writes while an Intune batch waits for CA work to finish. */
    private Duration intuneProcessingPollInterval = Duration.ofMinutes(2);
    /** Intune receives a deterministic failure instead of one batch blocking the source forever. */
    private Duration intuneTransactionTimeout = Duration.ofHours(6);

    @PostConstruct
    void validate() {
        if (claimBatchSize < 1 || claimBatchSize > 500) {
            throw new IllegalStateException(
                    "certping.iot.revocation.claim-batch-size must be between 1 and 500");
        }
        if (maxDispatchAttempts < 1 || maxDispatchAttempts > 50) {
            throw new IllegalStateException(
                    "certping.iot.revocation.max-dispatch-attempts must be between 1 and 50");
        }
        if (publishConcurrency < 1 || publishConcurrency > 64) {
            throw new IllegalStateException(
                    "certping.iot.revocation.publish-concurrency must be between 1 and 64");
        }
        requirePositive(maxOperationAge, "max-operation-age");
        requirePositive(claimLease, "claim-lease");
        requirePositive(responseTimeout, "response-timeout");
        requirePositive(intuneProcessingPollInterval, "intune-processing-poll-interval");
        requirePositive(intuneTransactionTimeout, "intune-transaction-timeout");
    }

    private static void requirePositive(Duration value, String property) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalStateException(
                    "certping.iot.revocation." + property + " must be positive");
        }
    }
}
