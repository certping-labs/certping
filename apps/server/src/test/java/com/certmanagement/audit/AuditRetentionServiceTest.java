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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The retention setting's rules: its range, its reason, its confirmation, its grace, and the months a run keeps. */
class AuditRetentionServiceTest {

    /** A Saturday, a minute before the daily run. */
    private static final Instant NOW = Instant.parse("2026-10-10T04:29:00Z");
    private static final Instant LONG_AGO = Instant.parse("2026-01-01T00:00:00Z");
    private static final String DAILY_0430 = "0 30 4 * * *";

    /** global_settings, in memory. */
    private final Map<String, GlobalSettingsEntity> table = new HashMap<>();
    private GlobalSettingsRepository settings;
    private AuditRecorder recorder;
    private AuditEventStore store;
    private SchedulerExecutionPolicy executionPolicy;
    private AuditRetentionService service;

    @BeforeEach
    void setUp() {
        settings = mock(GlobalSettingsRepository.class);
        when(settings.findById(anyString())).thenAnswer(call -> Optional.ofNullable(table.get(call.<String>getArgument(0))));
        when(settings.findByKeyForUpdate(anyString()))
                .thenAnswer(call -> Optional.ofNullable(table.get(call.<String>getArgument(0))));
        when(settings.findAllById(anyIterable())).thenAnswer(call -> {
            List<GlobalSettingsEntity> rows = new ArrayList<>();
            call.<Iterable<String>>getArgument(0).forEach(key -> Optional.ofNullable(table.get(key)).ifPresent(rows::add));
            return rows;
        });
        when(settings.save(any())).thenAnswer(call -> {
            GlobalSettingsEntity row = call.getArgument(0);
            table.put(row.getKey(), row);
            return row;
        });
        recorder = mock(AuditRecorder.class);
        store = mock(AuditEventStore.class);
        executionPolicy = mock(SchedulerExecutionPolicy.class);
        when(executionPolicy.canRun(AuditRetentionJob.JOB)).thenReturn(true);
        when(store.oldestPartitionMonth()).thenReturn(Optional.of(YearMonth.of(2023, 10)));
        service = new AuditRetentionService(settings, recorder, store, executionPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC), DAILY_0430, Duration.ofHours(24));
        stored(AuditRetentionService.SETTING_KEY, "12", LONG_AGO);
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 37, 0, -1, 120})
    void aPeriodOutsideSixToThirtySixMonthsIsRefusedWithItsCode(int months) {
        assertThatThrownBy(() -> service.update(months, "contract"))
                .isInstanceOf(AuditRetentionOutOfRangeException.class)
                .isInstanceOf(BadRequestException.class)
                .satisfies(e -> {
                    AuditRetentionOutOfRangeException refused = (AuditRetentionOutOfRangeException) e;
                    assertThat(refused.getMinMonths()).isEqualTo(6);
                    assertThat(refused.getMaxMonths()).isEqualTo(36);
                });
        assertThat(AuditRetentionOutOfRangeException.CODE).isEqualTo("AUDIT_RETENTION_OUT_OF_RANGE");
        verify(settings, never()).save(any());
        verify(recorder, never()).record(any());
    }

    @Test
    void aMissingPeriodIsOutOfRangeToo() {
        assertThatThrownBy(() -> service.update(null, "contract"))
                .isInstanceOf(AuditRetentionOutOfRangeException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {6, 36})
    void theBoundsThemselvesAreAccepted(int months) {
        AuditRetentionResponse response = service.update(months, "contract");

        assertThat(response.months()).isEqualTo(months);
        assertThat(response.previousMonths()).isEqualTo(12);
        assertThat(table.get(AuditRetentionService.SETTING_KEY).getValue()).isEqualTo(Integer.toString(months));
    }

    @Test
    void untilASuperAdminConfirmsNothingIsScheduled() {
        AuditRetentionResponse view = service.view();

        assertThat(view.confirmed()).isFalse();
        assertThat(view.confirmedAt()).isNull();
        assertThat(view.effectiveFrom()).isNull();
        assertThat(view.months()).isEqualTo(12);
        assertThat(view.oldestRetainedMonth()).isEqualTo("2025-10");
        assertThat(service.current().confirmed()).isFalse();
    }

    @Test
    void savingTheSameValueConfirmsItAndTheFirstConfirmationStartsTheGrace() {
        GatewayRequestContext.set(7, null, "req-1", "admin@certping.test");

        AuditRetentionResponse response = service.update(12, "  Keep a year,\nper policy‮\u0000 ");

        assertThat(response.confirmed()).isTrue();
        assertThat(response.confirmedAt()).isEqualTo(NOW);
        assertThat(response.previousMonths()).isNull();
        // Not the 04:30 run a minute away: the first confirmation waits out its day of grace.
        assertThat(response.effectiveFrom()).isEqualTo(Instant.parse("2026-10-11T04:30:00Z"));
        assertThat(table.get(AuditRetentionService.CONFIRMED_AT_KEY).getValue()).isEqualTo(NOW.toString());
        assertThat(table.get(AuditRetentionService.CONFIRMED_AT_KEY).getUpdatedBy()).isEqualTo(7L);
        assertThat(table.get(AuditRetentionService.GRACE_UNTIL_KEY).getValue())
                .isEqualTo(NOW.plus(Duration.ofHours(24)).toString());
        assertThat(table.get(AuditRetentionService.SETTING_KEY).getUpdatedAt().toInstant()).isEqualTo(LONG_AGO);

        List<AuditEventRow> rows = recorded();
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("audit.retention_confirmed");
        AuditEventRow row = rows.get(0);
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.summary()).isEqualTo("Confirmed that audit events are kept for 12 months");
        assertThat(row.details().attributes())
                .containsEntry("reason", "Keep a year, per policy")
                .containsEntry("firstConfirmation", "true")
                .containsEntry("effectiveFrom", "2026-10-11T04:30:00Z");
        assertThat(AuditEventType.AUDIT_RETENTION_CONFIRMED.internalOnlyAttributes()).containsExactly("reason");
    }

    @Test
    void aChangeIsRecordedAsAChangeAndAConfirmationWithTheReasonForThePlatformOnly() {
        confirmedLongAgo();
        GatewayRequestContext.set(7, null, "req-1", "admin@certping.test");

        service.update(6, "Contract ends in March");

        List<AuditEventRow> rows = recorded();
        assertThat(rows).extracting(AuditEventRow::event)
                .containsExactly("audit.retention_changed", "audit.retention_confirmed");
        AuditEventRow change = rows.get(0);
        assertThat(change.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(change.summary()).isEqualTo("Changed how long audit events are kept to 6 months");
        assertThat(change.details().changes()).containsExactly(new AuditChange("months", "12", "6"));
        assertThat(change.details().attributes()).containsEntry("reason", "Contract ends in March")
                .containsEntry("effectiveFrom", "2026-10-11T04:30:00Z");
        assertThat(rows.get(1).details().attributes()).containsEntry("firstConfirmation", "false");
        assertThat(AuditEventType.AUDIT_RETENTION_CHANGED.internalOnlyAttributes()).containsExactly("reason");
        assertThat(table.get(AuditRetentionService.SETTING_KEY).getUpdatedBy()).isEqualTo(7L);
    }

    @Test
    void shorteningRestartsTheGrace() {
        confirmedLongAgo();

        AuditRetentionResponse response = service.update(6, "contract");

        assertThat(response.effectiveFrom()).isEqualTo(Instant.parse("2026-10-11T04:30:00Z"));
        assertThat(response.oldestRetainedMonth()).isEqualTo("2026-04");
        assertThat(response.oldestStoredMonth()).isEqualTo("2023-10");
        assertThat(response.retentionDays()).isEqualTo(183);
        assertThat(service.inGrace(service.current(), NOW.plus(Duration.ofHours(23)))).isTrue();
        assertThat(service.inGrace(service.current(), NOW.plus(Duration.ofHours(24)))).isFalse();
    }

    @Test
    void lengtheningOrSavingAgainDoesNotDeferAnAlreadyDueRun() {
        confirmedLongAgo();

        AuditRetentionResponse longer = service.update(24, "longer history");
        assertThat(longer.effectiveFrom()).isEqualTo(Instant.parse("2026-10-10T04:30:00Z"));
        assertThat(service.inGrace(service.current(), NOW)).isFalse();

        AuditRetentionResponse again = service.update(24, "still right");
        assertThat(again.effectiveFrom()).isEqualTo(Instant.parse("2026-10-10T04:30:00Z"));
        assertThat(table.get(AuditRetentionService.GRACE_UNTIL_KEY).getValue()).isEqualTo(LONG_AGO.toString());
    }

    @Test
    void aMissingRowIsTheDefaultAndIsCreatedOnTheFirstSave() {
        table.clear();

        assertThat(service.current().months()).isEqualTo(12);
        assertThat(service.current().changedAt()).isNull();
        service.update(24, "longer history");

        assertThat(table.get("audit_retention_months").getValue()).isEqualTo("24");
        assertThat(recorded()).extracting(AuditEventRow::event)
                .containsExactly("audit.retention_changed", "audit.retention_confirmed");
    }

    @Test
    void aValueEditedOutOfRangeByHandIsNotUsable() {
        stored(AuditRetentionService.SETTING_KEY, "3", NOW);
        assertThat(service.current().usable()).isFalse();
        stored(AuditRetentionService.SETTING_KEY, "twelve", NOW);
        assertThat(service.current()).extracting(AuditRetentionService.Setting::months,
                AuditRetentionService.Setting::usable).containsExactly(12, false);
        stored(AuditRetentionService.SETTING_KEY, " 18 ", NOW);
        assertThat(service.current().usable()).isTrue();
    }

    @Test
    void theReasonIsRequiredAndAtMostFiveHundredCharacters() {
        assertThatThrownBy(() -> service.update(6, null)).isInstanceOf(BadRequestException.class)
                .isNotInstanceOf(AuditRetentionOutOfRangeException.class);
        assertThatThrownBy(() -> service.update(6, " ​\t\n ")).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.update(6, "x".repeat(501))).isInstanceOf(BadRequestException.class);
        assertThat(AuditRetentionService.cleanReason("é".repeat(500))).hasSize(500);
        assertThat(AuditRetentionService.cleanReason("😀".repeat(500))).hasSize(1000);
        verify(recorder, never()).record(any());
    }

    @Test
    void aRunKeepsTheCurrentMonthAndTheMonthsBeforeIt() {
        YearMonth october = YearMonth.of(2026, 10);

        assertThat(AuditRetentionService.cutoff(october, 12)).isEqualTo(Instant.parse("2025-10-01T00:00:00Z"));
        assertThat(AuditRetentionService.cutoff(october, 6)).isEqualTo(Instant.parse("2026-04-01T00:00:00Z"));
        assertThat(AuditRetentionService.cutoff(YearMonth.of(2027, 1), 36))
                .isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));
        assertThat(AuditRetentionService.oldestRetainedMonth(october, 12)).isEqualTo(YearMonth.of(2025, 10));
        assertThat(AuditRetentionService.retentionDays(36)).isEqualTo(1096);
    }

    @Test
    void theRunApplyingASettingIsAtOrAfterTheGracePeriodsEnd() {
        Instant graceUntil = Instant.parse("2026-10-11T23:59:00Z");

        assertThat(service.effectiveFrom(graceUntil, Instant.parse("2026-10-10T23:59:00Z")))
                .isEqualTo(Instant.parse("2026-10-12T04:30:00Z"));
        assertThat(service.effectiveFrom(null, Instant.parse("2026-10-10T04:30:00Z")))
                .isEqualTo(Instant.parse("2026-10-10T04:30:00Z"));
        assertThat(service.effectiveFrom(Instant.parse("2026-10-10T04:30:00Z"), Instant.parse("2026-10-10T04:30:00Z")))
                .isEqualTo(Instant.parse("2026-10-10T04:30:00Z"));
    }

    @Test
    void deletionWouldStartAtTheFirstRunOfTheConfiguredScheduleAfterTheConfiguredGrace() {
        AuditRetentionService custom = new AuditRetentionService(settings, recorder, store, executionPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC), "0 15 2 * * *", Duration.ofHours(36));

        AuditRetentionResponse view = custom.view();

        // 2026-10-10T04:29Z + 36h = 2026-10-11T16:29Z; the next 02:15 run is on the 12th.
        assertThat(view.deletionWouldStartAt()).isEqualTo(Instant.parse("2026-10-12T02:15:00Z"));
        assertThat(view.deletionHeldBy()).isNull();
        assertThat(service.view().deletionWouldStartAt()).isEqualTo(Instant.parse("2026-10-11T04:30:00Z"));
    }

    @Test
    void whatASaveNowWouldGetIsWhatItGets() {
        confirmedLongAgo();
        Instant wouldStart = service.view().deletionWouldStartAt();

        AuditRetentionResponse saved = service.update(6, "contract");

        assertThat(saved.effectiveFrom()).isEqualTo(wouldStart);
        assertThat(recorded()).allSatisfy(row ->
                assertThat(row.details().attributes()).containsEntry("effectiveFrom", saved.effectiveFrom().toString()));
    }

    @Test
    void withTheKillSwitchOffNothingWouldStartAndTheHoldIsNamed() {
        when(executionPolicy.canRun(AuditRetentionJob.JOB)).thenReturn(false);

        AuditRetentionResponse view = service.view();

        assertThat(view.deletionWouldStartAt()).isNull();
        assertThat(view.deletionHeldBy()).isEqualTo("KILL_SWITCH");
        assertThat(view.automaticDeletionEnabled()).isFalse();
    }

    @Test
    void withTheJobAllowedNothingHoldsDeletion() {
        AuditRetentionResponse view = service.view();

        assertThat(view.deletionHeldBy()).isNull();
        assertThat(view.deletionWouldStartAt()).isEqualTo(Instant.parse("2026-10-11T04:30:00Z"));
    }

    private void confirmedLongAgo() {
        stored(AuditRetentionService.CONFIRMED_AT_KEY, LONG_AGO.toString(), LONG_AGO);
        stored(AuditRetentionService.GRACE_UNTIL_KEY, LONG_AGO.toString(), LONG_AGO);
    }

    private List<AuditEventRow> recorded() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).record(rows.capture());
        return rows.getAllValues();
    }

    private void stored(String key, String value, Instant updatedAt) {
        table.put(key, GlobalSettingsEntity.builder().key(key).value(value)
                .updatedAt(updatedAt.atOffset(ZoneOffset.UTC)).build());
    }
}
