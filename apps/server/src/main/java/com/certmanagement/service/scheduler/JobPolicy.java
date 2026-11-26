// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.certmanagement.service.scheduler.JobTier.CUSTOMER_PROTECTION;
import static com.certmanagement.service.scheduler.JobTier.FEATURE_WORK;
import static com.certmanagement.service.scheduler.JobTier.PLATFORM_OBLIGATION;

/**
 * The one registry of background jobs: every {@code @Scheduled} method ({@link RegisteredJob}) and
 * every {@link DrainableCron} ({@link CronJobFor}) names an entry here, and
 * {@code JobPolicyRegistrationTest} fails when one does not.
 *
 * <p>Each entry declares its {@link JobTier}, an optional ops kill switch (a PLATFORM-scope flag that
 * pauses the job during an incident without touching the product), the product feature flags a
 * {@link JobTier#FEATURE_WORK} job needs. The env switch
 * {@code certping.jobs.<jobName>.enabled} (default true) applies to every entry.
 *
 * <table>
 *   <caption>Job tiers</caption>
 *   <tr><th>Job</th><th>Tier</th><th>Kill switch</th><th>Feature flags</th></tr>
 *   <tr><td>mark-expired-certs</td><td>CUSTOMER_PROTECTION</td><td>EXPIRY_MARKING</td><td>-</td></tr>
 *   <tr><td>trigger-renewals</td><td>CUSTOMER_PROTECTION</td><td>AUTO_RENEWAL</td><td>-</td></tr>
 *   <tr><td>retry-renewals</td><td>CUSTOMER_PROTECTION</td><td>AUTO_RENEWAL</td><td>-</td></tr>
 *   <tr><td>recover-stalled-renewals</td><td>CUSTOMER_PROTECTION</td><td>-</td><td>-</td></tr>
 *   <tr><td>trigger-expiry-alerts</td><td>CUSTOMER_PROTECTION</td><td>EXPIRY_ALERTS</td><td>-</td></tr>
 *   <tr><td>process-iot-certificate-revocations</td><td>CUSTOMER_PROTECTION</td><td>-</td><td>-</td></tr>
 *   <tr><td>process-intune-certificate-revocations</td><td>CUSTOMER_PROTECTION</td><td>-</td><td>-</td></tr>
 *   <tr><td>warn-certping-dns-key-expiry</td><td>CUSTOMER_PROTECTION</td><td>-</td><td>-</td></tr>
 *   <tr><td>trigger-iot-identity-sync</td><td>FEATURE_WORK</td><td>-</td><td>IOT_DEVICE_MANAGEMENT</td></tr>
 *   <tr><td>trigger-iot-activity-digest</td><td>FEATURE_WORK</td><td>-</td><td>IOT_DEVICE_MANAGEMENT</td></tr>
 *   <tr><td>trigger-iot-fleet-health-check</td><td>FEATURE_WORK</td><td>-</td><td>IOT_DEVICE_MANAGEMENT</td></tr>
 *   <tr><td>expiry-cleanup</td><td>PLATFORM_OBLIGATION</td><td>EXPIRED_CERT_SOFT_DELETE</td><td>-</td></tr>
 *   <tr><td>soft-delete-purge</td><td>PLATFORM_OBLIGATION</td><td>SOFT_DELETE_PURGE</td><td>-</td></tr>
 *   <tr><td>queue-alert</td><td>PLATFORM_OBLIGATION</td><td>QUEUE_DEPTH_ALERTS</td><td>-</td></tr>
 *   <tr><td>scheduler-supervisor</td><td>PLATFORM_OBLIGATION</td><td>-</td><td>-</td></tr>
 *   <tr><td>feature-flag-shared-sync</td><td>PLATFORM_OBLIGATION</td><td>-</td><td>-</td></tr>
 *   <tr><td>feature-lifecycle-reconcile</td><td>PLATFORM_OBLIGATION</td><td>FEATURE_LIFECYCLE_RECONCILE</td><td>-</td></tr>
 *   <tr><td>feature-lifecycle-transitions</td><td>PLATFORM_OBLIGATION</td><td>-</td><td>-</td></tr>
 *   <tr><td>audit-partitions</td><td>PLATFORM_OBLIGATION</td><td>-</td><td>-</td></tr>
 *   <tr><td>audit-retention</td><td>PLATFORM_OBLIGATION</td><td>AUDIT_RETENTION_PURGE</td><td>-</td></tr>
 *   <tr><td>telemetry-report</td><td>PLATFORM_OBLIGATION</td><td>-</td><td>-</td></tr>
 * </table>
 *
 * <p>Why the borderline ones sit where they do: IoT revocations (Intune included) revoke
 * certificates a customer already relies on being revocable, so they keep running when IoT is off.
 * {@code recover-stalled-renewals} has no kill
 * switch: it sends nothing, and pausing automatic renewal must not leave a manual renewal {@code RENEWING} for good.
 * The CertPing DNS key expiry warning tells admins before their certificates stop renewing, whatever the product
 * flags say. {@code scheduler-supervisor}
 * and {@code feature-flag-shared-sync} are the machinery the policy itself runs on, so they never
 * consult it. The feature lifecycle jobs pause the records of switched-off features and resume them,
 * so they must run exactly when product flags are off: {@code feature-lifecycle-transitions} applies
 * a super admin's switch-off or switch-on (forced; never paused), while
 * {@code feature-lifecycle-reconcile} is the baseline and backstop sweep, held by its ops switch
 * until the baseline preview has been reviewed. {@code audit-partitions} keeps the audit trail's
 * monthly partitions created ahead of time; recording audit events is an obligation whatever the
 * product flags say, and pausing it would only send rows to the default partition, so it has no kill
 * switch. {@code audit-retention} drops the audit months older than the
 * retention setting: keeping personal data (IP addresses) no longer than promised is an obligation whatever
 * the product flags say, but deleting is irreversible, so ops can hold it with {@code AUDIT_RETENTION_PURGE}
 * during an incident or a legal hold.
 */
public enum JobPolicy {

    MARK_EXPIRED_CERTS("mark-expired-certs", CUSTOMER_PROTECTION, FeatureFlags.EXPIRY_MARKING, Set.of()),
    TRIGGER_RENEWALS("trigger-renewals", CUSTOMER_PROTECTION, FeatureFlags.AUTO_RENEWAL, Set.of()),
    RETRY_RENEWALS("retry-renewals", CUSTOMER_PROTECTION, FeatureFlags.AUTO_RENEWAL, Set.of()),
    RECOVER_STALLED_RENEWALS("recover-stalled-renewals", CUSTOMER_PROTECTION, null, Set.of()),
    TRIGGER_EXPIRY_ALERTS("trigger-expiry-alerts", CUSTOMER_PROTECTION, FeatureFlags.EXPIRY_ALERTS, Set.of()),
    PROCESS_IOT_CERTIFICATE_REVOCATIONS(
            "process-iot-certificate-revocations", CUSTOMER_PROTECTION, null, Set.of()),
    PROCESS_INTUNE_CERTIFICATE_REVOCATIONS(
            "process-intune-certificate-revocations", CUSTOMER_PROTECTION, null, Set.of()),
    WARN_CERTPING_DNS_KEY_EXPIRY("warn-certping-dns-key-expiry", CUSTOMER_PROTECTION, null, Set.of()),

    TRIGGER_IOT_IDENTITY_SYNC("trigger-iot-identity-sync", FEATURE_WORK,
            null, Set.of(FeatureFlags.IOT_DEVICE_MANAGEMENT)),
    TRIGGER_IOT_ACTIVITY_DIGEST("trigger-iot-activity-digest", FEATURE_WORK,
            null, Set.of(FeatureFlags.IOT_DEVICE_MANAGEMENT)),
    TRIGGER_IOT_FLEET_HEALTH_CHECK("trigger-iot-fleet-health-check", FEATURE_WORK,
            null, Set.of(FeatureFlags.IOT_DEVICE_MANAGEMENT)),

    EXPIRY_CLEANUP("expiry-cleanup", PLATFORM_OBLIGATION, FeatureFlags.EXPIRED_CERT_SOFT_DELETE, Set.of()),
    SOFT_DELETE_PURGE("soft-delete-purge", PLATFORM_OBLIGATION, FeatureFlags.SOFT_DELETE_PURGE, Set.of()),
    QUEUE_ALERT("queue-alert", PLATFORM_OBLIGATION, FeatureFlags.QUEUE_DEPTH_ALERTS, Set.of()),
    SCHEDULER_SUPERVISOR("scheduler-supervisor", PLATFORM_OBLIGATION, null, Set.of()),
    FEATURE_FLAG_SHARED_SYNC("feature-flag-shared-sync", PLATFORM_OBLIGATION, null, Set.of()),
    FEATURE_LIFECYCLE_RECONCILE("feature-lifecycle-reconcile", PLATFORM_OBLIGATION,
            FeatureFlags.FEATURE_LIFECYCLE_RECONCILE, Set.of()),
    FEATURE_LIFECYCLE_TRANSITIONS("feature-lifecycle-transitions", PLATFORM_OBLIGATION, null, Set.of()),
    AUDIT_PARTITIONS("audit-partitions", PLATFORM_OBLIGATION, null, Set.of()),
    AUDIT_RETENTION("audit-retention", PLATFORM_OBLIGATION, FeatureFlags.AUDIT_RETENTION_PURGE, Set.of()),
    /** The opt-in usage report; its own switch is certping.telemetry.enabled (off), this entry only names it. */
    TELEMETRY_REPORT("telemetry-report", PLATFORM_OBLIGATION, null, Set.of());

    private static final Map<String, JobPolicy> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(JobPolicy::jobName, Function.identity()));

    private final String jobName;
    private final JobTier tier;
    private final String killSwitchFlag;
    private final Set<String> featureFlags;

    JobPolicy(String jobName, JobTier tier, String killSwitchFlag, Set<String> featureFlags) {
        this.jobName = jobName;
        this.tier = tier;
        this.killSwitchFlag = killSwitchFlag;
        this.featureFlags = featureFlags;
    }

    /** The entry for a job name, or empty for an unknown job. */
    public static Optional<JobPolicy> byName(String jobName) {
        return Optional.ofNullable(jobName).map(BY_NAME::get);
    }

    public String jobName() { return jobName; }

    public JobTier tier() { return tier; }

    /** The PLATFORM-scope ops flag that pauses this job, or {@code null} when it has none. */
    public String killSwitchFlag() { return killSwitchFlag; }

    /** The product flags a {@link JobTier#FEATURE_WORK} job needs; empty for every other tier. */
    public Set<String> featureFlags() { return featureFlags; }

    String enabledProperty() {
        return "certping.jobs." + jobName + ".enabled";
    }
}
