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

@Data
@Component
@Validated
@ConfigurationProperties(prefix = "certping.iot.device-sync")
public class IotDeviceSyncProperties {
    private int maxExplicitDevices = 500;
    private int maxAllDevices = 5_000;

    @NotNull
    private Duration cooldown = Duration.ofMinutes(15);

    @PostConstruct
    void validate() {
        if (maxExplicitDevices < 1 || maxExplicitDevices > 10_000) {
            throw new IllegalStateException(
                    "certping.iot.device-sync.max-explicit-devices must be between 1 and 10000");
        }
        if (maxAllDevices < 1 || maxAllDevices > 100_000) {
            throw new IllegalStateException(
                    "certping.iot.device-sync.max-all-devices must be between 1 and 100000");
        }
        if (cooldown == null || cooldown.isNegative()) {
            throw new IllegalStateException(
                    "certping.iot.device-sync.cooldown must not be negative");
        }
    }
}
