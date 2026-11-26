// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CronRun;
import com.certmanagement.repository.CronRunRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SchedulerSupervisorTest {

    @Mock private CronRunRepository repo;
    @Mock private DrainRunner drainRunner;
    @Mock private SchedulerExecutionPolicy executionPolicy;

    private SchedulerSupervisor supervisor;

    /** Fixed clock — 2026-07-20 07:00 UTC. Well past mark-expired-certs's 02:00 fire
     *  (5h delay, within maxDelay=6h). */
    private final Clock fixedClock = Clock.fixed(
            Instant.parse("2026-07-20T07:00:00Z"), ZoneOffset.UTC);

    private final OffsetDateTime now = OffsetDateTime.ofInstant(fixedClock.instant(), ZoneOffset.UTC);

    @BeforeEach
    void setUp() {
        when(executionPolicy.canRun(anyString())).thenReturn(true);
        supervisor = new SchedulerSupervisor(repo, drainRunner, executionPolicy, fixedClock);
    }

    @Test
    void allCronsFresh_nothingHappens() {
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, now.minusSeconds(1))));
        }

        supervisor.supervise();

        verify(drainRunner, never()).runDrain(anyString());
    }

    @Test
    void missedDailyCronWithinMaxDelay_triggersCatchup() {
        OffsetDateTime longAgo = now.minusDays(2);
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, longAgo)));
        }

        supervisor.supervise();

        verify(drainRunner).runDrain("mark-expired-certs");
    }

    @Test
    void missedButBeyondMaxDelay_skipped() {
        // trigger-renewals fires 03:00 UTC daily, maxDelay=6h. Clock at 10:30 puts delay=7h30m > 6h.
        Clock lateClock = Clock.fixed(Instant.parse("2026-07-20T10:30:00Z"), ZoneOffset.UTC);
        SchedulerSupervisor lateSupervisor =
                new SchedulerSupervisor(repo, drainRunner, executionPolicy, lateClock);
        OffsetDateTime lateNow = OffsetDateTime.ofInstant(lateClock.instant(), ZoneOffset.UTC);

        for (CronDefinition c : CronDefinition.values()) {
            if (c == CronDefinition.TRIGGER_RENEWALS) {
                when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, lateNow.minusDays(2))));
            } else {
                when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, lateNow.minusSeconds(1))));
            }
        }

        lateSupervisor.supervise();

        verify(drainRunner, never()).runDrain("trigger-renewals");
    }


    @Test
    void noPriorRun_catchesUpWithinMaxDelay() {
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.empty());
        }

        supervisor.supervise();

        verify(drainRunner).runDrain("mark-expired-certs");
    }

    @Test
    void missedJobDisabledByPolicy_isNotCaughtUp() {
        when(executionPolicy.canRun("mark-expired-certs")).thenReturn(false);
        OffsetDateTime longAgo = now.minusDays(2);
        for (CronDefinition cron : CronDefinition.values()) {
            when(repo.findById(cron.name)).thenReturn(Optional.of(cronRun(cron.name, 0, longAgo)));
        }

        supervisor.supervise();

        verify(drainRunner, never()).runDrain("mark-expired-certs");
    }

    @Test
    void drainThrows_exceptionSwallowed() {
        OffsetDateTime longAgo = now.minusDays(2);
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, longAgo)));
        }
        doThrow(new RuntimeException("boom")).when(drainRunner).runDrain("mark-expired-certs");

        supervisor.supervise();   // must not throw

        verify(drainRunner).runDrain("mark-expired-certs");
    }

    @Test
    void supervisorTwice_bothTicksTriggerCatchupsIndependently() {
        OffsetDateTime longAgo = now.minusDays(2);
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, longAgo)));
        }

        supervisor.supervise();
        supervisor.supervise();

        verify(drainRunner, atLeast(2)).runDrain("mark-expired-certs");
    }

    @Test
    void justAfterCatchup_secondTickSeesFreshActivity_skips() {
        OffsetDateTime justNow = now.minusSeconds(1);
        for (CronDefinition c : CronDefinition.values()) {
            when(repo.findById(c.name)).thenReturn(Optional.of(cronRun(c.name, 0, justNow)));
        }

        supervisor.supervise();

        verify(drainRunner, never()).runDrain(anyString());
    }

    private static CronRun cronRun(String name, int count, OffsetDateTime lastActivity) {
        CronRun r = new CronRun();
        r.setCronName(name);
        r.setActivePodCount(count);
        r.setLastActivityAt(lastActivity);
        return r;
    }
}
