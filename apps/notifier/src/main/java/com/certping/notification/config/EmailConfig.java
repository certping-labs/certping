// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "email")
@Data
public class EmailConfig {
    private String senderAddress;
    private String supportAddress;
    /**
     * App dashboard base URL, env-driven so emails link to the install that sent them.
     * Set from CERTPING_URL (self-hosted) or FRONTEND_BASE_URL.
     */
    private String frontendBaseUrl;

    /**
     * The contact address shown in email footers: EMAIL_SUPPORT_ADDRESS, otherwise the sender
     * address (EMAIL_FROM, or no-reply at the host of the install's URL).
     */
    public String getSupportAddress() {
        if (supportAddress != null && !supportAddress.isBlank()) {
            return supportAddress;
        }
        return SenderAddresses.resolve(senderAddress, frontendBaseUrl);
    }
}
