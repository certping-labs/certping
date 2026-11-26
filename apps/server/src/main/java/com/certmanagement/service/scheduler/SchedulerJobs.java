// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * In-process cron entry points for the drain jobs. Execution policy ({@link JobPolicy} via
 * {@link SchedulerExecutionPolicy}) and draining ({@link DrainRunner}) are centralized collaborators.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SchedulerJobs {

    private final DrainRunner drainRunner;
    private final SchedulerExecutionPolicy executionPolicy;

    @RegisteredJob("mark-expired-certs")
    @Scheduled(cron = "${certping.jobs.mark-expired-certs.cron}", zone = "UTC")
    public void markExpiredCerts() { safeRun("mark-expired-certs"); }

    @RegisteredJob("trigger-renewals")
    @Scheduled(cron = "${certping.jobs.trigger-renewals.cron}", zone = "UTC")
    public void triggerRenewals() { safeRun("trigger-renewals"); }

    @RegisteredJob("retry-renewals")
    @Scheduled(cron = "${certping.jobs.retry-renewals.cron:0 */5 * * * *}", zone = "UTC")
    public void retryRenewals() { safeRun("retry-renewals"); }

    @RegisteredJob("recover-stalled-renewals")
    @Scheduled(cron = "${certping.jobs.recover-stalled-renewals.cron:0 40 * * * *}", zone = "UTC")
    public void recoverStalledRenewals() { safeRun("recover-stalled-renewals"); }

    @RegisteredJob("trigger-expiry-alerts")
    @Scheduled(cron = "${certping.jobs.trigger-expiry-alerts.cron}", zone = "UTC")
    public void triggerExpiryAlerts() { safeRun("trigger-expiry-alerts"); }

    @RegisteredJob("trigger-iot-identity-sync")
    @Scheduled(cron = "${certping.jobs.trigger-iot-identity-sync.cron}", zone = "UTC")
    public void triggerIotIdentitySync() { safeRun("trigger-iot-identity-sync"); }

    @RegisteredJob("process-iot-certificate-revocations")
    @Scheduled(cron = "${certping.jobs.process-iot-certificate-revocations.cron:*/10 * * * * *}", zone = "UTC")
    public void processIotCertificateRevocations() {
        safeRun("process-iot-certificate-revocations");
    }

    @RegisteredJob("process-intune-certificate-revocations")
    @Scheduled(cron = "${certping.jobs.process-intune-certificate-revocations.cron:0 * * * * *}", zone = "UTC")
    public void processIntuneCertificateRevocations() {
        safeRun("process-intune-certificate-revocations");
    }

    @RegisteredJob("trigger-iot-activity-digest")
    @Scheduled(cron = "${certping.jobs.trigger-iot-activity-digest.cron:0 0 7 * * *}", zone = "UTC")
    public void triggerIotActivityDigest() { safeRun("trigger-iot-activity-digest"); }

    @RegisteredJob("trigger-iot-fleet-health-check")
    @Scheduled(cron = "${certping.jobs.trigger-iot-fleet-health-check.cron:0 20 * * * *}", zone = "UTC")
    public void triggerIotFleetHealthCheck() { safeRun("trigger-iot-fleet-health-check"); }

    @RegisteredJob("expiry-cleanup")
    @Scheduled(cron = "${certping.jobs.expiry-cleanup.cron}", zone = "UTC")
    public void expiryCleanup() { safeRun("expiry-cleanup"); }

    private void safeRun(String jobName) {
        if (!executionPolicy.canRun(jobName)) {
            return;
        }
        try {
            drainRunner.runDrain(jobName);
        } catch (Exception exception) {
            log.error("[SchedulerJobs] {} FAILED: {}", jobName, exception.getMessage(), exception);
        }
    }
}
