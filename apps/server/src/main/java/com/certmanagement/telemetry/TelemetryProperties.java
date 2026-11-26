// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Opt-in usage reporting ({@code CERTPING_TELEMETRY_*}). Off unless {@code enabled} is true; what is
 * sent is exactly {@link TelemetryReport} and is documented in {@code docs/self-hosting.md#privacy-and-telemetry}.
 */
@Component
@ConfigurationProperties(prefix = "certping.telemetry")
@Getter
@Setter
public class TelemetryProperties {

    private boolean enabled = false;
    /** Where the report is posted. */
    private String endpoint = "https://telemetry.certping.com/v1/report";
    /** How often, once the server has been up for {@link #initialDelay}. */
    private Duration interval = Duration.ofHours(24);
    private Duration initialDelay = Duration.ofMinutes(60);
}
