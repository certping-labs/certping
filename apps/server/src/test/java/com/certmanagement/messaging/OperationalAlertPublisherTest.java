// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OperationalAlertPublisherTest {

    @Test
    void usesAllDbSuperAdminsWhenPresent() {
        List<String> recipients = OperationalAlertPublisher.resolveRecipients(
                List.of("a@example.com", "b@example.com"), "fallback@example.com");
        assertThat(recipients).containsExactly("a@example.com", "b@example.com");
    }

    @Test
    void trimsAndDeduplicates() {
        List<String> recipients = OperationalAlertPublisher.resolveRecipients(
                List.of("a@example.com", " a@example.com ", "b@example.com"), null);
        assertThat(recipients).containsExactly("a@example.com", "b@example.com");
    }

    @Test
    void fallsBackToConfiguredWhenDbEmptyOrNull() {
        assertThat(OperationalAlertPublisher.resolveRecipients(List.of(), "fallback@example.com"))
                .containsExactly("fallback@example.com");
        assertThat(OperationalAlertPublisher.resolveRecipients(null, "fallback@example.com"))
                .containsExactly("fallback@example.com");
    }

    @Test
    void dbResultsTakePrecedenceOverFallback() {
        List<String> recipients = OperationalAlertPublisher.resolveRecipients(
                List.of("real@example.com"), "fallback@example.com");
        assertThat(recipients).containsExactly("real@example.com");
    }

    @Test
    void filtersPlaceholderAndBlanks() {
        List<String> recipients = OperationalAlertPublisher.resolveRecipients(
                Arrays.asList("super_admin@certping.local", "  ", null, "real@example.com"),
                "fallback@example.com");
        assertThat(recipients).containsExactly("real@example.com");
    }

    @Test
    void emptyWhenNothingUsable() {
        assertThat(OperationalAlertPublisher.resolveRecipients(List.of("super_admin@certping.local"), "   "))
                .isEmpty();
        assertThat(OperationalAlertPublisher.resolveRecipients(null, "super_admin@certping.local"))
                .isEmpty();
    }
}
