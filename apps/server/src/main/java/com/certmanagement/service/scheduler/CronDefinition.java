// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import java.time.Duration;

/**
 * Crons the supervisor watches for missed fires. Excludes very-frequent crons
 * (every-minute, every-15-min, every-30-min, hourly) — those self-heal on their next natural
 * fire, so catchup adds no value.
 *
 * <p>{@code defaultCronExpression} matches the default in application.yaml. The supervisor
 * resolves the ACTUAL cron expression from Spring's {@code Environment} at startup (which
 * honours {@code CERTPING_JOBS_*_CRON} environment overrides), falling back to this
 * default only when no property is set.
 */
public enum CronDefinition {

    MARK_EXPIRED_CERTS              ("mark-expired-certs",              "0 0 2 * * *",  Duration.ofHours(6)),
    TRIGGER_RENEWALS                ("trigger-renewals",                "0 0 3 * * *",  Duration.ofHours(6)),
    TRIGGER_EXPIRY_ALERTS           ("trigger-expiry-alerts",           "0 0 8 * * *",  Duration.ofHours(12));

    public final String name;
    public final String defaultCronExpression;
    public final Duration maxDelay;

    CronDefinition(String name, String defaultCronExpression, Duration maxDelay) {
        this.name = name;
        this.defaultCronExpression = defaultCronExpression;
        this.maxDelay = maxDelay;
    }

    /** The Spring property key that owns the runtime cron expression for this job. */
    public String cronPropertyKey() {
        return "certping.jobs." + name + ".cron";
    }
}
