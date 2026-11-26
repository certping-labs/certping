// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.notification;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The actions an organization can turn off are pinned, so making one more of them optional is a
 * visible change; every notice of security, failure, expiry or service changes is always sent.
 */
class NotificationCategoryTest {

    @Test
    void exactlyTheseActionsCanBeTurnedOff() {
        Map<NotificationCategory, Set<String>> byCategory = Arrays.stream(NotificationCategory.values())
                .collect(Collectors.toMap(category -> category, NotificationCategory::actions));

        assertThat(byCategory).containsOnly(
                Map.entry(NotificationCategory.CERTIFICATE_ACTIVITY,
                        Set.of("CERT_ISSUANCE_SUCCESS", "CERT_RENEWAL_SUCCESS", "CERT_DEPLOYMENT_SUCCESS")),
                Map.entry(NotificationCategory.REPORTS,
                        Set.of("IOT_ACTIVITY_DIGEST")));
        assertThat(NotificationCategory.of("CERT_RENEWAL_SUCCESS")).contains(NotificationCategory.CERTIFICATE_ACTIVITY);
        assertThat(NotificationCategory.of("IOT_ACTIVITY_DIGEST")).contains(NotificationCategory.REPORTS);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // Security and account
            "RESET_PASSWORD", "PASSWORD_CHANGE_SUCCESS", "CERT_REVOKED",
            // Failures, expiry and action needed
            "CERT_ISSUANCE_FAILED", "CERT_RENEWAL_FAILED", "CERT_DEPLOYMENT_FAILED", "CERT_MANUAL_TXT_READY",
            "CERT_RENEWED_NOT_DEPLOYED", "CERT_EXPIRY_ALERT", "CERT_EXPIRED", "SCHEDULER_CREDENTIAL_PARSE_FAILED",
            "SCHEDULER_RENEWAL_SEND_FAILED", "IOT_CRITICAL_ALERT", "IOT_WARNING_ALERT", "CERTPING_DNS_KEY_EXPIRING",
            // Service changes
            "FEATURE_PAUSED", "FEATURE_RESUMED",
            // Not an organization's notice, or not one yet
            "SYSTEM_DLQ_ALERT", "SOME_ACTION_ADDED_LATER"})
    void everyOtherActionIsAlwaysSent(String action) {
        assertThat(NotificationCategory.of(action)).isEmpty();
    }

    @Test
    void nothingIsACategoryButItsOwnName() {
        assertThat(NotificationCategory.of(null)).isEmpty();
        assertThat(NotificationCategory.named("REPORTS")).contains(NotificationCategory.REPORTS);
        assertThat(NotificationCategory.named("reports")).isEmpty();
        assertThat(NotificationCategory.named(null)).isEmpty();
    }
}
