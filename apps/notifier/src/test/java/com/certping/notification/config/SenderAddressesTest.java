// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SenderAddressesTest {

    @Test
    void configuredAddressWins() {
        assertThat(SenderAddresses.resolve(" certping@lab.test ", "https://certping.example"))
                .isEqualTo("certping@lab.test");
    }

    @Test
    void derivesNoReplyFromTheInstallUrlHost() {
        assertThat(SenderAddresses.resolve("", "https://Certping.Example:8443/app")).isEqualTo("no-reply@certping.example");
        assertThat(SenderAddresses.resolve(null, "http://localhost")).isEqualTo("no-reply@localhost");
    }

    @Test
    void nothingToDeriveFrom() {
        assertThat(SenderAddresses.resolve(null, null)).isNull();
        assertThat(SenderAddresses.resolve(" ", "")).isNull();
        assertThat(SenderAddresses.resolve(null, "not a url")).isNull();
    }

    @Test
    void supportAddressFallsBackToTheSender() {
        EmailConfig config = new EmailConfig();
        config.setFrontendBaseUrl("https://certping.example");
        assertThat(config.getSupportAddress()).isEqualTo("no-reply@certping.example");
        config.setSenderAddress("certping@certping.example");
        assertThat(config.getSupportAddress()).isEqualTo("certping@certping.example");
        config.setSupportAddress("help@certping.example");
        assertThat(config.getSupportAddress()).isEqualTo("help@certping.example");
    }
}
