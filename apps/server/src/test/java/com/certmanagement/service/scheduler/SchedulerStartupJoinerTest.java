// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CronRun;
import com.certmanagement.repository.CronRunRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.TaskScheduler;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SchedulerStartupJoinerTest {

    @Mock private CronRunRepository repo;
    @Mock private DrainRunner drainRunner;
    @Mock private TaskScheduler taskScheduler;
    @Mock private SchedulerExecutionPolicy executionPolicy;

    @InjectMocks private SchedulerStartupJoiner joiner;

    private ArgumentCaptor<Runnable> submittedWork;

    @BeforeEach
    void setUp() {
        submittedWork = ArgumentCaptor.forClass(Runnable.class);
    }

    @Test
    void applicationReady_submitsWorkWithoutAccessingSchedulerStateInline() {
        joiner.onApplicationReady();

        verify(taskScheduler).schedule(submittedWork.capture(), any(Instant.class));
        verifyNoInteractions(repo, drainRunner);
    }

    @Test
    void rejectedSubmission_doesNotFailApplicationReadiness() {
        when(taskScheduler.schedule(any(Runnable.class), any(Instant.class)))
                .thenThrow(new TaskRejectedException("scheduler unavailable"));

        joiner.onApplicationReady();

        verifyNoInteractions(repo, drainRunner);
    }

    @Test
    void submittedWork_restoresCallingThreadMdc() {
        when(repo.findAll()).thenReturn(List.of());
        MDC.put("requestId", "parent-request");
        MDC.put("correlationId", "parent-correlation");

        try {
            runSubmittedWork();

            assertThat(MDC.get("requestId")).isEqualTo("parent-request");
            assertThat(MDC.get("correlationId")).isEqualTo("parent-correlation");
        } finally {
            MDC.clear();
        }
    }

    @BeforeEach
    void allowKnownJobs() {
        org.mockito.Mockito.lenient()
                .when(executionPolicy.canRun(anyString()))
                .thenReturn(true);
    }

    @Test
    void emptyTable_doesNothing() {
        when(repo.findAll()).thenReturn(List.of());

        runSubmittedWork();

        verifyNoInteractions(drainRunner);
        verify(repo, never()).resetIfStale(anyString(), any());
    }

    @Test
    void countZero_isIgnored() {
        when(repo.findAll()).thenReturn(List.of(cronRun("job-a", 0, minutesAgo(5))));

        runSubmittedWork();

        verifyNoInteractions(drainRunner);
        verify(repo, never()).resetIfStale(anyString(), any());
    }

    @Test
    void countPositiveWithinTtl_joinsDrain() {
        when(repo.findAll()).thenReturn(List.of(cronRun("job-a", 2, minutesAgo(5))));

        runSubmittedWork();

        verify(drainRunner).runDrain("job-a");
        verify(repo, never()).resetIfStale(anyString(), any());
    }

    @Test
    void activeDrainDisabledByPolicy_isNotJoined() {
        when(repo.findAll()).thenReturn(List.of(cronRun("trigger-renewals", 2, minutesAgo(5))));
        when(executionPolicy.canRun("trigger-renewals")).thenReturn(false);

        runSubmittedWork();

        verify(drainRunner, never()).runDrain(anyString());
    }

    @Test
    void countPositiveButStale_resetsAndDoesNotJoin() {
        when(repo.findAll()).thenReturn(List.of(cronRun("job-a", 3, minutesAgo(180))));
        when(repo.resetIfStale(eq("job-a"), any())).thenReturn(1);

        runSubmittedWork();

        verify(repo).resetIfStale(eq("job-a"), any());
        verifyNoInteractions(drainRunner);
    }

    @Test
    void drainThrows_exceptionSwallowed() {
        when(repo.findAll()).thenReturn(List.of(cronRun("job-a", 1, minutesAgo(1))));
        doThrow(new RuntimeException("boom")).when(drainRunner).runDrain("job-a");

        runSubmittedWork();

        verify(drainRunner).runDrain("job-a");
    }

    @Test
    void multipleRows_eachHandledIndependently() {
        when(repo.findAll()).thenReturn(List.of(
                cronRun("job-a",     2, minutesAgo(5)),      // joins
                cronRun("job-b",     0, minutesAgo(5)),      // ignored
                cronRun("mark-exp",  1, minutesAgo(180))     // reset (stale)
        ));
        when(repo.resetIfStale(eq("mark-exp"), any())).thenReturn(1);

        runSubmittedWork();

        verify(drainRunner, times(1)).runDrain("job-a");
        verify(drainRunner, never()).runDrain("job-b");
        verify(drainRunner, never()).runDrain("mark-exp");
        verify(repo).resetIfStale(eq("mark-exp"), any());
    }

    private void runSubmittedWork() {
        joiner.onApplicationReady();
        verify(taskScheduler).schedule(submittedWork.capture(), any(Instant.class));
        submittedWork.getValue().run();
        verifyNoMoreInteractions(taskScheduler);
    }

    private static CronRun cronRun(String name, int count, OffsetDateTime lastActivity) {
        CronRun r = new CronRun();
        r.setCronName(name);
        r.setActivePodCount(count);
        r.setLastActivityAt(lastActivity);
        return r;
    }

    private static OffsetDateTime minutesAgo(int minutes) {
        return OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(minutes);
    }
}
