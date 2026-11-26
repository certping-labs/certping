// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditRetentionResponse;
import com.certmanagement.entity.GlobalSettingsEntity;
import com.certmanagement.exception.AuditRetentionOutOfRangeException;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.GlobalSettingsRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * How long audit events are kept: the platform-wide {@code global_settings.audit_retention_months} (default
 * {@value #DEFAULT_MONTHS}, a super admin may choose {@value #MIN_MONTHS} to {@value #MAX_MONTHS}), read and
 * saved here, and applied by {@link AuditRetentionJob}.
 *
 * <p>Retention drops whole monthly partitions: a run keeps the current month and the {@code months} before it,
 * so a row is kept for the period plus up to one month.
 *
 * <p>Nothing is ever deleted until a super admin has <b>confirmed</b> the period: every save, even of the value
 * already stored, sets {@code audit_retention_confirmed_at} and is recorded as an internal
 * {@code audit.retention_confirmed} row, with the reason internal-only; a save that changes the value is also an
 * {@code audit.retention_changed} row. Both are written in the save's transaction.
 *
 * <p>A save never deletes anything itself. The first confirmation, and any save that shortens the period, start a
 * grace period ({@code certping.jobs.audit-retention.grace}, a day by default, stored as
 * {@code audit_retention_grace_until}) during which the job skips its runs, so a period saved by mistake can be
 * put back before any month is dropped. Lengthening, or saving the same value again, does not move it: an
 * already-due run still runs, and keeps more. {@link AuditRetentionResponse#effectiveFrom()} says when the first
 * run applying the setting is, for the settings card to warn with.
 */
@Slf4j
@Service
public class AuditRetentionService {

    public static final String SETTING_KEY = "audit_retention_months";
    public static final String CONFIRMED_AT_KEY = "audit_retention_confirmed_at";
    public static final String GRACE_UNTIL_KEY = "audit_retention_grace_until";
    public static final int DEFAULT_MONTHS = 12;
    public static final int MIN_MONTHS = 6;
    public static final int MAX_MONTHS = 36;
    public static final int MAX_REASON_LENGTH = 500;
    /** {@code deletionHeldBy}: the job may not run here (its kill switch AUDIT_RETENTION_PURGE, or env switch). */
    public static final String HELD_BY_KILL_SWITCH = "KILL_SWITCH";

    private static final String DESCRIPTION = "Months audit events are kept before their monthly partition is"
            + " dropped (6-36). Rows are kept up to one extra month.";
    private static final String CONFIRMED_DESCRIPTION = "When a super admin last confirmed the audit retention"
            + " period; nothing is dropped before the first confirmation.";
    private static final String GRACE_DESCRIPTION = "The audit retention job drops nothing before this instant"
            + " (set by the first confirmation and by every shortening).";
    private static final double DAYS_PER_MONTH = 365.25 / 12;
    private static final DateTimeFormatter MONTH = DateTimeFormatter.ofPattern("yyyy-MM");
    /** Control and format characters (bidi overrides, zero-width), line and paragraph separators. */
    private static final Pattern UNPRINTABLE = Pattern.compile("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final GlobalSettingsRepository settings;
    private final AuditRecorder recorder;
    private final AuditEventStore store;
    private final SchedulerExecutionPolicy executionPolicy;
    private final Clock clock;
    private final CronExpression schedule;
    private final Duration grace;

    public AuditRetentionService(GlobalSettingsRepository settings, AuditRecorder recorder, AuditEventStore store,
                                 SchedulerExecutionPolicy executionPolicy, Clock clock,
                                 @Value("${certping.jobs.audit-retention.cron}") String cron,
                                 @Value("${certping.jobs.audit-retention.grace:24h}") Duration grace) {
        this.settings = settings;
        this.recorder = recorder;
        this.store = store;
        this.executionPolicy = executionPolicy;
        this.clock = clock;
        this.schedule = CronExpression.parse(cron);
        this.grace = grace.isNegative() ? Duration.ZERO : grace;
    }

    /**
     * The stored setting and what gates applying it.
     *
     * @param months       the period; {@link #DEFAULT_MONTHS} when the row is missing or not a number
     * @param changedAt    when the period last changed, or {@code null} when the row is missing
     * @param problem      why the stored value cannot be applied (not a number, out of range), or {@code null}
     * @param confirmedAt  when a super admin last confirmed it, or {@code null} when never: nothing is dropped
     * @param graceUntil   the job drops nothing before this, or {@code null} when there is no grace period
     */
    public record Setting(int months, Instant changedAt, String problem, Instant confirmedAt, Instant graceUntil) {

        /** Whether the retention job may apply it; a value edited out of range by hand is not applied. */
        public boolean usable() {
            return problem == null;
        }

        public boolean confirmed() {
            return confirmedAt != null;
        }
    }

    /** The stored setting; the documented default when the row is missing. One query for the three keys. */
    @Transactional(readOnly = true)
    public Setting current() {
        Map<String, GlobalSettingsEntity> rows = new HashMap<>();
        settings.findAllById(List.of(SETTING_KEY, CONFIRMED_AT_KEY, GRACE_UNTIL_KEY))
                .forEach(row -> rows.put(row.getKey(), row));
        Months months = parse(rows.get(SETTING_KEY));
        return new Setting(months.months(), months.changedAt(), months.problem(), instant(rows.get(CONFIRMED_AT_KEY)),
                instant(rows.get(GRACE_UNTIL_KEY)));
    }

    /** The setting as the settings card shows it. */
    @Transactional(readOnly = true)
    public AuditRetentionResponse view() {
        Setting setting = current();
        if (!setting.usable()) {
            log.warn("[AuditRetention] global_settings.{} cannot be applied ({}); the retention job will not drop"
                    + " anything until a super admin saves a valid period", SETTING_KEY, setting.problem());
        }
        return response(setting, null, clock.instant());
    }

    /**
     * Confirms the period, setting it to {@code months} first when it differs, for {@code reason}, and records
     * both in this transaction. The first confirmation and a shortening start the grace period; lengthening or
     * saving the same value does not move it.
     *
     * @throws AuditRetentionOutOfRangeException when {@code months} is missing or outside
     *                                           {@value #MIN_MONTHS}..{@value #MAX_MONTHS}
     * @throws BadRequestException               when the reason is empty, once cleaned, or too long
     */
    @Transactional
    public AuditRetentionResponse update(Integer months, String reason) {
        if (months == null || !inRange(months)) {
            throw new AuditRetentionOutOfRangeException(months, MIN_MONTHS, MAX_MONTHS);
        }
        String why = cleanReason(reason);
        Optional<GlobalSettingsEntity> row = settings.findByKeyForUpdate(SETTING_KEY);
        Months before = parse(row.orElse(null));
        Setting stored = current();
        Instant now = clock.instant();
        Long userId = GatewayRequestContext.getUserId() == null ? null : GatewayRequestContext.getUserId().longValue();

        boolean changed = row.isEmpty() || !before.usable() || before.months() != months;
        boolean first = !stored.confirmed();
        boolean shortened = changed && (!before.usable() || months < before.months());
        Instant graceUntil = first || shortened ? now.plus(grace) : stored.graceUntil();

        if (changed) {
            String storedBefore = row.map(GlobalSettingsEntity::getValue).orElse(null);
            GlobalSettingsEntity entity = row.orElseGet(() -> GlobalSettingsEntity.builder()
                    .key(SETTING_KEY).description(DESCRIPTION).build());
            entity.setValue(Integer.toString(months));
            entity.setUpdatedAt(now.atOffset(ZoneOffset.UTC));
            entity.setUpdatedBy(userId);
            settings.save(entity);
            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("effectiveFrom", effectiveFrom(graceUntil, now).toString());
            attributes.put("reason", why);
            recorder.record(AuditEvents.internal(AuditEventType.AUDIT_RETENTION_CHANGED, AuditSubject.builder()
                    .resourceRef(SETTING_KEY).name(SETTING_KEY).count(months)
                    .changes(List.of(new AuditChange("months", storedBefore, Integer.toString(months))))
                    .attributes(attributes).build()));
            log.info("[AuditRetention] audit retention set from {} to {} months by userId={}", storedBefore, months,
                    userId);
        }
        put(CONFIRMED_AT_KEY, now.toString(), CONFIRMED_DESCRIPTION, now, userId);
        if (graceUntil != null && !graceUntil.equals(stored.graceUntil())) {
            put(GRACE_UNTIL_KEY, graceUntil.toString(), GRACE_DESCRIPTION, now, userId);
        }
        Instant effectiveFrom = effectiveFrom(graceUntil, now);
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("effectiveFrom", effectiveFrom.toString());
        attributes.put("firstConfirmation", Boolean.toString(first));
        attributes.put("reason", why);
        recorder.record(AuditEvents.internal(AuditEventType.AUDIT_RETENTION_CONFIRMED, AuditSubject.builder()
                .resourceRef(SETTING_KEY).name(SETTING_KEY).count(months).attributes(attributes).build()));
        log.info("[AuditRetention] audit retention of {} months confirmed by userId={} (first={}); drops from {}",
                months, userId, first, effectiveFrom);
        // Built after the rows are written: the response's own reads cannot leave the save unrecorded.
        // The same instant as the rows: the response's effectiveFrom is the one recorded.
        return response(new Setting(months, changed ? now : stored.changedAt(), null, now, graceUntil),
                changed ? before.months() : null, now);
    }

    /** Whether a run at {@code now} must wait: the first confirmation or a shortening is in its grace period. */
    boolean inGrace(Setting setting, Instant now) {
        return setting.graceUntil() != null && now.isBefore(setting.graceUntil());
    }

    /** The start of the first scheduled run at or after both {@code now} and {@code graceUntil}. */
    Instant effectiveFrom(Instant graceUntil, Instant now) {
        Instant earliest = graceUntil == null || now.isAfter(graceUntil) ? now : graceUntil;
        // CronExpression.next is strictly after its argument; a nanosecond earlier makes it "at or after".
        return schedule.next(earliest.atZone(ZoneOffset.UTC).minusNanos(1)).toInstant();
    }

    /** The first instant kept by a run in {@code current} keeping {@code months}: every earlier month is dropped. */
    static Instant cutoff(YearMonth current, int months) {
        return oldestRetainedMonth(current, months).atDay(1).atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    /** The oldest month a run in {@code current} keeps: the current month and the {@code months} before it. */
    static YearMonth oldestRetainedMonth(YearMonth current, int months) {
        return current.minusMonths(months);
    }

    static long retentionDays(int months) {
        return Math.round(months * DAYS_PER_MONTH);
    }

    static boolean inRange(int months) {
        return months >= MIN_MONTHS && months <= MAX_MONTHS;
    }

    /**
     * The reason as stored: control and invisible formatting characters and line breaks become spaces, runs of
     * whitespace one space, and the ends are trimmed.
     *
     * @throws BadRequestException when nothing is left, or more than {@value #MAX_REASON_LENGTH} characters are
     */
    static String cleanReason(String reason) {
        String cleaned = reason == null ? ""
                : WHITESPACE.matcher(UNPRINTABLE.matcher(reason).replaceAll(" ")).replaceAll(" ").strip();
        if (cleaned.isEmpty()) {
            throw new BadRequestException("A reason is required.");
        }
        if (cleaned.codePointCount(0, cleaned.length()) > MAX_REASON_LENGTH) {
            throw new BadRequestException("The reason must be at most " + MAX_REASON_LENGTH + " characters.");
        }
        return cleaned;
    }

    private void put(String key, String value, String description, Instant now, Long userId) {
        GlobalSettingsEntity entity = settings.findById(key).orElseGet(() -> GlobalSettingsEntity.builder()
                .key(key).description(description).build());
        entity.setValue(value);
        entity.setUpdatedAt(now.atOffset(ZoneOffset.UTC));
        entity.setUpdatedBy(userId);
        settings.save(entity);
    }

    private AuditRetentionResponse response(Setting setting, Integer previousMonths, Instant now) {
        // Unconfirmed: no run drops anything, so there is no date; the months shown are what this month keeps.
        Instant effectiveFrom = setting.confirmed() ? effectiveFrom(setting.graceUntil(), now) : null;
        YearMonth runMonth = YearMonth.from(Objects.requireNonNullElse(effectiveFrom, now).atZone(ZoneOffset.UTC));
        boolean deletionEnabled = executionPolicy.canRun(AuditRetentionJob.JOB);
        String heldBy = deletionEnabled ? null : HELD_BY_KILL_SWITCH;
        return new AuditRetentionResponse(setting.months(), retentionDays(setting.months()), MIN_MONTHS, MAX_MONTHS,
                effectiveFrom, MONTH.format(oldestRetainedMonth(runMonth, setting.months())), oldestStoredMonth(),
                deletionEnabled, setting.changedAt(), previousMonths,
                setting.confirmed(), setting.confirmedAt(),
                deletionEnabled ? deletionWouldStartAt(now) : null, heldBy);
    }

    /**
     * The {@code effectiveFrom} a first confirmation or a shortening saved at {@code now} would get: the first run
     * of the configured schedule at or after the end of the configured grace period, which starts at {@code now}.
     */
    Instant deletionWouldStartAt(Instant now) {
        return effectiveFrom(now.plus(grace), now);
    }

    private String oldestStoredMonth() {
        try {
            return store.oldestPartitionMonth().map(MONTH::format).orElse(null);
        } catch (RuntimeException e) {
            log.warn("[AuditRetention] could not read the oldest audit partition ({})", e.getClass().getSimpleName());
            return null;
        }
    }

    private record Months(int months, Instant changedAt, String problem) {

        boolean usable() {
            return problem == null;
        }
    }

    private static Months parse(GlobalSettingsEntity row) {
        if (row == null) {
            return new Months(DEFAULT_MONTHS, null, null);
        }
        Instant changedAt = row.getUpdatedAt() == null ? null : row.getUpdatedAt().toInstant();
        int months;
        try {
            months = Integer.parseInt(row.getValue() == null ? "" : row.getValue().strip());
        } catch (NumberFormatException e) {
            return new Months(DEFAULT_MONTHS, changedAt, "not a whole number of months");
        }
        if (!inRange(months)) {
            return new Months(months, changedAt, "outside " + MIN_MONTHS + " to " + MAX_MONTHS + " months");
        }
        return new Months(months, changedAt, null);
    }

    private static Instant instant(GlobalSettingsEntity row) {
        if (row == null || row.getValue() == null || row.getValue().isBlank()) {
            return null;
        }
        try {
            return Instant.parse(row.getValue().strip());
        } catch (RuntimeException unparseable) {
            log.warn("[AuditRetention] global_settings.{} is not an instant; ignored", row.getKey());
            return null;
        }
    }
}
