// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import static java.time.temporal.ChronoUnit.SECONDS;

@Validated
@ConfigurationProperties(prefix = "app.integrations")
public record IntegrationProperties(
        @Valid @NotNull Delivery delivery
) {

    public record Delivery(
            @NotNull @DurationUnit(SECONDS) Duration connectTimeout,
            @NotNull @DurationUnit(SECONDS) Duration readTimeout
    ) {
    }
}
