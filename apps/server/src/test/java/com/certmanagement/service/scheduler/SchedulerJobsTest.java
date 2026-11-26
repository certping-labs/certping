// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;


import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SchedulerJobsTest {

    @Mock private DrainRunner drainRunner;
    @Mock private SchedulerExecutionPolicy executionPolicy;

    private SchedulerJobs jobs;

    @BeforeEach
    void setUp() {
        jobs = new SchedulerJobs(drainRunner, executionPolicy);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mark-expired-certs",
            "trigger-renewals",
            "trigger-expiry-alerts",
            "trigger-iot-identity-sync",
            "expiry-cleanup"
    })
    void enabledJob_delegatesToDrainRunner(String jobName) {
        when(executionPolicy.canRun(jobName)).thenReturn(true);

        invoke(jobName);

        verify(drainRunner).runDrain(jobName);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mark-expired-certs",
            "trigger-renewals",
            "trigger-expiry-alerts",
            "trigger-iot-identity-sync",
            "expiry-cleanup"
    })
    void disabledJob_doesNotStartDrain(String jobName) {
        when(executionPolicy.canRun(jobName)).thenReturn(false);

        invoke(jobName);

        verify(drainRunner, never()).runDrain(anyString());
    }

    @Test
    void drainFailure_isContained() {
        when(executionPolicy.canRun("trigger-renewals")).thenReturn(true);
        doThrow(new RuntimeException("oops")).when(drainRunner).runDrain("trigger-renewals");

        jobs.triggerRenewals();

        verify(drainRunner).runDrain("trigger-renewals");
    }

    private void invoke(String jobName) {
        switch (jobName) {
            case "mark-expired-certs" -> jobs.markExpiredCerts();
            case "trigger-renewals" -> jobs.triggerRenewals();
            case "trigger-expiry-alerts" -> jobs.triggerExpiryAlerts();
            case "trigger-iot-identity-sync" -> jobs.triggerIotIdentitySync();
            case "expiry-cleanup" -> jobs.expiryCleanup();
            default -> throw new IllegalArgumentException("Unknown test job " + jobName);
        }
    }
}
