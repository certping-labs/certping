// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeliveryTimeoutsTest {

    private static final Duration LEASE = Duration.ofMinutes(5);

    @Test
    void anSmtpSendIsBoundedByItsThreePhases() {
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, Duration.ofSeconds(30), LEASE);

        assertThat(timeouts.sendBudget()).isEqualTo(Duration.ofSeconds(90));
    }

    @Test
    void anAcsSendIsBoundedByItsFourPhases() {
        DeliveryTimeouts timeouts = new DeliveryTimeouts("acs", 0, 0, 0, Duration.ofSeconds(30), LEASE);

        assertThat(timeouts.sendBudget()).isEqualTo(Duration.ofMinutes(2));
    }

    @Test
    void aSendThatCouldOutlastTheClaimRefusesToStart() {
        assertThatThrownBy(() -> new DeliveryTimeouts("smtp", 100_000, 100_000, 100_000, Duration.ofSeconds(30), LEASE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("claim-lease");
    }

    @Test
    void anUnboundedSendRefusesToStart() {
        assertThatThrownBy(() -> new DeliveryTimeouts("smtp", 0, 0, 0, Duration.ofSeconds(30), LEASE))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aSendStartsOnlyWhileItCanFinishInsideTheClaim() {
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, Duration.ofSeconds(30), LEASE);

        assertThat(timeouts.fitsInLease(LEASE, Duration.ofSeconds(1))).isTrue();
        assertThat(timeouts.fitsInLease(LEASE, Duration.ofSeconds(210))).isFalse();
    }
}
