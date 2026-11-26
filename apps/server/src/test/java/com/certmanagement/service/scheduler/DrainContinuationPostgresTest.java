// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.repository.CronRunRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Drain continuation on real PostgreSQL: a drain capped by its row budget leaves its continuation marker in
 * {@code cron_runs}; a freshly started pod (new DrainRunner and supervisor, no memory of the first
 * run) continues it tick by tick from that marker until the backlog is drained and the marker cleared.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class DrainContinuationPostgresTest {

    private static final String JOB = "expiry-cleanup";

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    @Autowired private CronRunRepository repo;
    @Autowired private JdbcTemplate jdbc;

    /** Stands for the job's rows in the database: it outlives the pods that drain it. */
    private final AtomicInteger backlog = new AtomicInteger();
    private SchedulerExecutionPolicy policy;

    @BeforeEach
    void reset() {
        jdbc.update("DELETE FROM cron_runs");
        policy = mock(SchedulerExecutionPolicy.class);
        // Only the drain under test may run, so the supervisor's missed-fire pass stays idle.
        when(policy.canRun(anyString())).thenAnswer(call -> JOB.equals(call.getArgument(0)));
        when(policy.budgetFor(anyString())).thenReturn(new SchedulerExecutionPolicy.DrainBudget(2, Duration.ofHours(1)));
    }

    @Test
    void aCappedDrainContinuesOnTheNextTicksAfterARestartUntilDrained() {
        backlog.set(5);
        new DrainRunner(List.of(new BacklogJob(backlog)), repo, policy).runDrain(JOB);
        assertThat(backlog).hasValue(3);
        assertThat(marker()).as("capped by the row budget").isNotNull();

        // Restart: a new pod with no memory of the first run.
        BacklogJob job = new BacklogJob(backlog);
        SchedulerSupervisor supervisor = newPod(job);

        supervisor.supervise();
        assertThat(backlog).hasValue(1);
        assertThat(marker()).as("capped again").isNotNull();

        supervisor.supervise();
        assertThat(backlog).hasValue(0);
        assertThat(marker()).as("drained: nothing left to continue").isNull();

        int calls = job.calls.get();
        supervisor.supervise();
        assertThat(job.calls).as("no marker, no continuation").hasValue(calls);
    }

    @Test
    void aContinuationIsHeldWhileTheJobMayNotRun() {
        backlog.set(5);
        new DrainRunner(List.of(new BacklogJob(backlog)), repo, policy).runDrain(JOB);
        when(policy.canRun(JOB)).thenReturn(false);

        newPod(new BacklogJob(backlog)).supervise();

        assertThat(backlog).hasValue(3);
        assertThat(marker()).as("kept for when the job may run again").isNotNull();
    }

    @Test
    void aDrainAnotherPodIsRunningIsNotJoinedUnlessItsCounterIsStale() {
        jdbc.update("INSERT INTO cron_runs (cron_name, active_pod_count, last_activity_at, continuation_due_at)"
                + " VALUES (?, 1, NOW(), NOW())", JOB);
        OffsetDateTime staleCutoff = OffsetDateTime.now().minus(SchedulerStartupJoiner.STALE_AFTER);

        assertThat(repo.findIdleWithContinuationDue(staleCutoff)).as("running elsewhere").isEmpty();

        jdbc.update("UPDATE cron_runs SET last_activity_at = NOW() - INTERVAL '1 hour'");
        assertThat(repo.findIdleWithContinuationDue(staleCutoff)).as("leaked by a crashed pod").containsExactly(JOB);
    }

    private SchedulerSupervisor newPod(BacklogJob job) {
        return new SchedulerSupervisor(repo, new DrainRunner(List.of(job), repo, policy), policy, Clock.systemUTC());
    }

    private OffsetDateTime marker() {
        return jdbc.queryForObject("SELECT continuation_due_at FROM cron_runs WHERE cron_name = ?",
                OffsetDateTime.class, JOB);
    }

    /** A drain over {@code backlog}: one unit per iteration until none is left. */
    @CronJobFor(JOB)
    static class BacklogJob implements DrainableCron {
        private final AtomicInteger backlog;
        private final AtomicInteger calls = new AtomicInteger();

        BacklogJob(AtomicInteger backlog) {
            this.backlog = backlog;
        }

        @Override
        public boolean tryProcessOneEligible() {
            calls.incrementAndGet();
            return backlog.getAndUpdate(left -> Math.max(0, left - 1)) > 0;
        }
    }
}
