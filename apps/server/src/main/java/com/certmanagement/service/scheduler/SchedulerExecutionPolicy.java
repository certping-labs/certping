// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.service.FeatureFlagService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/**
 * Applies {@link JobPolicy} — the registry of every background job — at each entry point and inside
 * running drains.
 *
 * <p>A job may run only when it is registered, its environment enable flag is on, its ops kill switch (when any) is on, and — for {@link JobTier#FEATURE_WORK} —
 * every feature flag it needs is on platform-wide. Unknown jobs and evaluation failures are denied.
 * Flag lookups go through the cached resolver, so {@link DrainRunner} can re-check every iteration.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SchedulerExecutionPolicy {

    static final String DEFAULT_MAX_ROWS_PROPERTY = "certping.jobs.drain-budget.max-rows-per-run";
    static final String DEFAULT_MAX_DURATION_PROPERTY = "certping.jobs.drain-budget.max-run-duration";
    /** Generous enough for a normal day's backlog; a re-enabled feature drains the rest on later fires. */
    static final int DEFAULT_MAX_ROWS = 10_000;
    static final Duration DEFAULT_MAX_DURATION = Duration.ofMinutes(30);

    private final Environment environment;
    private final FeatureFlagService featureFlagService;

    /**
     * How much one drain run may process before it yields to the next fire.
     *
     * @param maxRows     iterations (rows, or batches for batch drains) per run
     * @param maxDuration wall-clock time per run
     */
    public record DrainBudget(int maxRows, Duration maxDuration) {}

    /**
     * Returns whether the named job is permitted to execute now.
     *
     * @param jobName canonical {@link JobPolicy#jobName()}
     * @return {@code true} only when every configured gate allows execution
     */
    public boolean canRun(String jobName) {
        try {
            Optional<JobPolicy> found = JobPolicy.byName(jobName);
            if (found.isEmpty()) {
                log.warn("[SchedulerPolicy] Unknown job {} — skipping", jobName);
                return false;
            }
            JobPolicy jobPolicy = found.get();
            if (!environment.getProperty(jobPolicy.enabledProperty(), Boolean.class, true)) {
                log.debug("[SchedulerPolicy] {} disabled by environment — skipping", jobName);
                return false;
            }
            if (jobPolicy.killSwitchFlag() != null && !featureFlagService.isEnabled(jobPolicy.killSwitchFlag(), null)) {
                log.info("[SchedulerPolicy] {} paused by kill switch {} — skipping", jobName, jobPolicy.killSwitchFlag());
                return false;
            }
            for (String featureFlag : jobPolicy.featureFlags()) {
                if (!featureFlagService.isEnabled(featureFlag, null)) {
                    log.info("[SchedulerPolicy] {} disabled by feature flag {} — skipping", jobName, featureFlag);
                    return false;
                }
            }
            return true;
        } catch (RuntimeException exception) {
            log.error("[SchedulerPolicy] Could not evaluate execution policy for {} — skipping",
                    jobName, exception);
            return false;
        }
    }

    /**
     * Row-level gate for {@link JobTier#FEATURE_WORK} drains: whether a row of {@code organizationId}
     * may be processed. Always {@code true} for the other tiers. Cached per flag and organization, so
     * calling it per claimed row adds no query in the steady state.
     *
     * @param jobName        canonical {@link JobPolicy#jobName()}
     * @param organizationId the row's organization; {@code null} falls back to the platform answer
     * @return {@code false} when any of the job's feature flags is off for the organization, or the
     *         lookup fails (fail closed: the row is skipped, not processed)
     */
    public boolean canProcessForOrg(String jobName, Long organizationId) {
        try {
            JobPolicy jobPolicy = JobPolicy.byName(jobName)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown job " + jobName));
            if (jobPolicy.tier() != JobTier.FEATURE_WORK) {
                return true;
            }
            for (String featureFlag : jobPolicy.featureFlags()) {
                if (!featureFlagService.isEnabled(featureFlag, organizationId)) {
                    log.debug("[SchedulerPolicy] {} skips org {}: feature flag {} is off",
                            jobName, organizationId, featureFlag);
                    return false;
                }
            }
            return true;
        } catch (RuntimeException exception) {
            log.error("[SchedulerPolicy] Could not evaluate org gate for {} org={} — skipping row",
                    jobName, organizationId, exception);
            return false;
        }
    }

    /**
     * The per-run budget for a drain: {@code certping.jobs.<jobName>.max-rows-per-run} /
     * {@code .max-run-duration}, else the {@code certping.jobs.drain-budget.*} defaults, else
     * {@value #DEFAULT_MAX_ROWS} rows and 30 minutes. Non-positive or unparsable values fall back to
     * the default so a typo cannot unbound a drain.
     */
    public DrainBudget budgetFor(String jobName) {
        int maxRows = readPositiveInt("certping.jobs." + jobName + ".max-rows-per-run",
                readPositiveInt(DEFAULT_MAX_ROWS_PROPERTY, DEFAULT_MAX_ROWS));
        Duration maxDuration = readPositiveDuration("certping.jobs." + jobName + ".max-run-duration",
                readPositiveDuration(DEFAULT_MAX_DURATION_PROPERTY, DEFAULT_MAX_DURATION));
        return new DrainBudget(maxRows, maxDuration);
    }

    private int readPositiveInt(String property, int fallback) {
        try {
            Integer value = environment.getProperty(property, Integer.class);
            return value != null && value > 0 ? value : fallback;
        } catch (RuntimeException exception) {
            log.warn("[SchedulerPolicy] Invalid {} — using {}", property, fallback);
            return fallback;
        }
    }

    private Duration readPositiveDuration(String property, Duration fallback) {
        String raw = environment.getProperty(property);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            Duration value = DurationStyle.detectAndParse(raw.strip());
            return value.isNegative() || value.isZero() ? fallback : value;
        } catch (RuntimeException exception) {
            log.warn("[SchedulerPolicy] Invalid {}='{}' — using {}", property, raw, fallback);
            return fallback;
        }
    }
}
