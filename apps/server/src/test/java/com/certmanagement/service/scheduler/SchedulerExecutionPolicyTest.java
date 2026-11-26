// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SchedulerExecutionPolicyTest {

    @Mock private Environment environment;
    @Mock private FeatureFlagService featureFlagService;

    private SchedulerExecutionPolicy policy;

    @BeforeEach
    void setUp() {
        policy = new SchedulerExecutionPolicy(environment, featureFlagService);
    }

    @ParameterizedTest
    @CsvSource({
            "mark-expired-certs, EXPIRY_MARKING",
            "trigger-renewals, AUTO_RENEWAL",
            "trigger-expiry-alerts, EXPIRY_ALERTS",
            "trigger-iot-identity-sync, IOT_DEVICE_MANAGEMENT",
            "expiry-cleanup, EXPIRED_CERT_SOFT_DELETE",
            "soft-delete-purge, SOFT_DELETE_PURGE",
            "queue-alert, QUEUE_DEPTH_ALERTS",
            "audit-retention, AUDIT_RETENTION_PURGE"
    })
    void enabledJobWithFeatureFlag_canRun(String jobName, String featureFlag) {
        enableEnvironment(jobName);
        when(featureFlagService.isEnabled(featureFlag, null)).thenReturn(true);

        assertThat(policy.canRun(jobName)).isTrue();
    }

    @Test
    void environmentKillSwitch_deniesBeforeFeatureLookup() {
        when(environment.getProperty(
                "certping.jobs.trigger-renewals.enabled", Boolean.class, true)).thenReturn(false);

        assertThat(policy.canRun("trigger-renewals")).isFalse();
        verify(featureFlagService, never()).isEnabled(anyString(), eq(null));
    }

    @Test
    void auditRetentionKillSwitch_deniesTheDrops() {
        enableEnvironment("audit-retention");
        when(featureFlagService.isEnabled(FeatureFlags.AUDIT_RETENTION_PURGE, null)).thenReturn(false);

        assertThat(policy.canRun("audit-retention")).isFalse();
    }

    @Test
    void featureKillSwitch_deniesJob() {
        enableEnvironment("trigger-renewals");
        when(featureFlagService.isEnabled(FeatureFlags.AUTO_RENEWAL, null)).thenReturn(false);

        assertThat(policy.canRun("trigger-renewals")).isFalse();
    }

    @Test
    void featureLookupFailure_failsClosed() {
        enableEnvironment("trigger-renewals");
        when(featureFlagService.isEnabled(FeatureFlags.AUTO_RENEWAL, null))
                .thenThrow(new IllegalStateException("database unavailable"));

        assertThat(policy.canRun("trigger-renewals")).isFalse();
    }

    @Test
    void invalidEnvironmentValue_failsClosed() {
        when(environment.getProperty(
                "certping.jobs.trigger-renewals.enabled", Boolean.class, true))
                .thenThrow(new IllegalArgumentException("invalid boolean"));

        assertThat(policy.canRun("trigger-renewals")).isFalse();
        verify(featureFlagService, never()).isEnabled(anyString(), eq(null));
    }

    @Test
    void unknownJob_isDeniedWithoutReadingConfiguration() {
        assertThat(policy.canRun("unknown-job")).isFalse();
        verify(environment, never()).getProperty(anyString(), eq(Boolean.class), eq(true));
    }

    // ── tiers ──────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"process-iot-certificate-revocations", "process-intune-certificate-revocations"})
    void iotRevocations_areCustomerProtection_andIgnoreTheIotFlag(String jobName) {
        enableEnvironment(jobName);

        assertThat(policy.canRun(jobName)).isTrue();
        verify(featureFlagService, never()).isEnabled(anyString(), eq(null));
    }

    @Test
    void rowGate_featureWorkSkipsOrgsWithTheFeatureOff() {
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 5L)).thenReturn(false);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 6L)).thenReturn(true);

        assertThat(policy.canProcessForOrg("trigger-iot-identity-sync", 5L)).isFalse();
        assertThat(policy.canProcessForOrg("trigger-iot-identity-sync", 6L)).isTrue();
    }

    @Test
    void rowGate_customerProtectionNeverSkipsRows() {
        assertThat(policy.canProcessForOrg("trigger-renewals", 5L)).isTrue();
        verify(featureFlagService, never()).isEnabled(anyString(), eq(5L));
    }

    @Test
    void rowGate_failsClosed() {
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 5L)).thenThrow(new IllegalStateException("db"));

        assertThat(policy.canProcessForOrg("trigger-iot-identity-sync", 5L)).isFalse();
        assertThat(policy.canProcessForOrg("unknown-job", 5L)).isFalse();
    }

    // ── budget ─────────────────────────────────────────────────────────

    @Test
    void budget_defaultsWhenNothingIsConfigured() {
        SchedulerExecutionPolicy.DrainBudget budget = policy.budgetFor("trigger-renewals");

        assertThat(budget.maxRows()).isEqualTo(SchedulerExecutionPolicy.DEFAULT_MAX_ROWS);
        assertThat(budget.maxDuration()).isEqualTo(SchedulerExecutionPolicy.DEFAULT_MAX_DURATION);
    }

    @Test
    void budget_perJobOverridesTheGlobalDefault() {
        lenient().when(environment.getProperty(SchedulerExecutionPolicy.DEFAULT_MAX_ROWS_PROPERTY, Integer.class)).thenReturn(500);
        lenient().when(environment.getProperty("certping.jobs.retry-renewals.max-rows-per-run", Integer.class)).thenReturn(50);
        lenient().when(environment.getProperty(SchedulerExecutionPolicy.DEFAULT_MAX_DURATION_PROPERTY)).thenReturn("10m");
        lenient().when(environment.getProperty("certping.jobs.retry-renewals.max-run-duration")).thenReturn("PT2M");

        SchedulerExecutionPolicy.DrainBudget budget = policy.budgetFor("retry-renewals");

        assertThat(budget.maxRows()).isEqualTo(50);
        assertThat(budget.maxDuration()).isEqualTo(java.time.Duration.ofMinutes(2));
    }

    @Test
    void budget_invalidOrNonPositiveValuesFallBack() {
        // Lenient: the defaults are read with other keys on the same mock method.
        lenient().when(environment.getProperty("certping.jobs.retry-renewals.max-rows-per-run", Integer.class)).thenReturn(0);
        lenient().when(environment.getProperty("certping.jobs.retry-renewals.max-run-duration")).thenReturn("soon");

        SchedulerExecutionPolicy.DrainBudget budget = policy.budgetFor("retry-renewals");

        assertThat(budget.maxRows()).isEqualTo(SchedulerExecutionPolicy.DEFAULT_MAX_ROWS);
        assertThat(budget.maxDuration()).isEqualTo(SchedulerExecutionPolicy.DEFAULT_MAX_DURATION);
    }

    private void enableEnvironment(String jobName) {
        when(environment.getProperty(
                "certping.jobs." + jobName + ".enabled", Boolean.class, true)).thenReturn(true);
    }
}
