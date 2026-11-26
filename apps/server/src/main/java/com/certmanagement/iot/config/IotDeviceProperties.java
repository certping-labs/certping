// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.config;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/** Operational bounds for device-source messages, health freshness, and sync recovery. */
@Data
@Component
@Validated
@ConfigurationProperties(prefix = "certping.iot")
public class IotDeviceProperties {
    @NotNull
    private Duration healthStaleAfter = Duration.ofMinutes(15);
    @NotNull
    private Duration maxAgentClockSkew = Duration.ofMinutes(10);
    @NotNull
    private Duration pendingSyncRetryAfter = Duration.ofMinutes(1);
    @NotNull
    private Duration runningSyncTimeout = Duration.ofHours(2);
    @NotNull
    private Duration profileResponseTimeout = Duration.ofHours(2);
    @NotNull
    private Duration syncInterval = Duration.ofHours(1);

    @PostConstruct
    void validate() {
        requirePositive("health-stale-after", healthStaleAfter);
        requirePositive("max-agent-clock-skew", maxAgentClockSkew);
        requirePositive("pending-sync-retry-after", pendingSyncRetryAfter);
        requirePositive("running-sync-timeout", runningSyncTimeout);
        requirePositive("profile-response-timeout", profileResponseTimeout);
        requirePositive("sync-interval", syncInterval);
    }

    private static void requirePositive(String property, Duration duration) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            throw new IllegalStateException(
                    "certping.iot." + property + " must be greater than zero");
        }
    }
}
