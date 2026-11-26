// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.config.ClockConfig;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.lifecycle.AccessLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.DiscoveryLifecycleRepository;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.certmanagement.service.lifecycle.LifecycleFixtures.DISCOVERY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Forced transitions on real PostgreSQL with the REAL flag resolver and flag service: a
 * super admin's change is recorded with the write, applied by the walk whatever the ops switch says,
 * emailed exactly once per organization it switched off (here: running discovery scans, which a pause cancels), nets to nothing when undone before it was
 * applied, survives a pod restart mid-walk and is recovered by the backstop when its after-commit run
 * was lost. Organizations that had the feature off already are BASELINE and left alone while the
 * {@code FEATURE_LIFECYCLE_RECONCILE} switch is off.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ImportAutoConfiguration(JacksonAutoConfiguration.class)
@Import({DiscoveryLifecycleRepository.class, CertificateLifecycleRepository.class,
        AccessLifecycleRepository.class, FeatureLifecycleConfiguration.class, DiscoveryLifecycle.class,
        CertificateDeploymentLifecycle.class, FeatureLifecycleRegistry.class, FeatureLifecycleLock.class,
        FeatureLifecycleStateStore.class, FeatureLifecycleNotifier.class, FeatureLifecycleReconciler.class,
        FeatureLifecycleService.class, FeatureFlagChangeAudit.class, ClockConfig.class,
        FeatureFlagResolver.class, FeatureFlagService.class, ForcedFlagChanges.class, ForcedTransitionStore.class,
        ForcedTransitionWalker.class, FeatureLifecycleSweeper.class, BaselineClassifier.class,
        FeatureLifecycleBackstopJob.class, SchedulerExecutionPolicy.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ForcedTransitionPostgresTest {

    /** The rows are captured, not stored: audit_events has its own tests. */
    @MockitoBean private com.certmanagement.audit.AuditRecorder auditRecorder;

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

    @MockitoBean private OrgAdminNotificationPublisher publisher;

    @Autowired private FeatureFlagService flags;
    @Autowired private ForcedTransitionWalker walker;
    @Autowired private FeatureLifecycleBackstopJob backstop;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private LifecycleFixtures fixtures;

    @BeforeEach
    void seed() {
        fixtures = new LifecycleFixtures(jdbc);
        fixtures.reset();
        reset(publisher);
        reset(publisher);
    }

    @Test
    void aForcedGlobalSwitchOffAppliesWithTheOpsSwitchOffAndEmailsOnlyTheOrganizationsItSwitchedOff() {
        long acme = fixtures.organization("acme", "B2B", 3);
        long optedOut = fixtures.organization("optedout", "B2B", 2);
        fixtures.orgOverride(optedOut, DISCOVERY, false, false);

        flags.updateGlobal(DISCOVERY, false, "incident");
        walker.apply(fixtures.newestTransitionId(), budget());

        assertThat(fixtures.cancelledScans(acme)).isEqualTo(3);
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), eq(String.valueOf(acme)), anyString(), any(),
                eq(acme + ":" + DISCOVERY + ":PAUSED:1"));
        assertThat(fixtures.runningScans(optedOut)).as("already off: baseline, untouched while the switch is off")
                .isEqualTo(2);
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), eq(String.valueOf(optedOut)), anyString(),
                any(), anyString());
        assertThat(fixtures.transitions()).extracting(row -> row.get("status")).containsExactly("COMPLETE");

        walker.apply(fixtures.newestTransitionId(), budget());
        fixtures.ageTransitions();
        backstop.applyStalledTransitions();
        verify(publisher, times(1)).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void theOpsSwitchOffKeepsTheBaselineAndBackstopSweepIdleAndOnPausesSilently() {
        long optedOut = fixtures.organization("optedout", "B2B", 2);
        fixtures.orgOverride(optedOut, DISCOVERY, false, false);

        backstop.reconcileAll();
        assertThat(fixtures.runningScans(optedOut)).isEqualTo(2);

        fixtures.switchBaseline(true);
        backstop.reconcileAll();

        assertThat(fixtures.cancelledScans(optedOut)).isEqualTo(2);
        ArgumentCaptor<com.certmanagement.audit.AuditEventRow> rows =
                ArgumentCaptor.forClass(com.certmanagement.audit.AuditEventRow.class);
        verify(auditRecorder, org.mockito.Mockito.atLeastOnce()).record(rows.capture());
        assertThat(rows.getAllValues()).filteredOn(row -> "feature.paused".equals(row.event())).singleElement()
                .satisfies(row -> {
                    assertThat(row.actorJob()).isEqualTo("feature-lifecycle-reconcile");
                    assertThat(row.details().attributes()).containsEntry("cause", "ORG_OVERRIDE");
                });
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void aSwitchOffUndoneBeforeItWasAppliedPausesNothingAndEmailsNobody() {
        long acme = fixtures.organization("acme", "B2B", 3);

        flags.updateGlobal(DISCOVERY, false, null);
        long off = fixtures.newestTransitionId();
        flags.updateGlobal(DISCOVERY, true, null);
        walker.apply(off, budget());
        walker.apply(fixtures.newestTransitionId(), budget());

        assertThat(fixtures.runningScans(acme)).isEqualTo(3);
        assertThat(fixtures.transitions()).extracting(row -> row.get("status"))
                .containsExactly("SUPERSEDED", "COMPLETE");
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void offOnOffBeforeTheReconcileSendsExactlyOneEmail() {
        long acme = fixtures.organization("acme", "B2B", 3);

        flags.updateGlobal(DISCOVERY, false, null);
        flags.updateGlobal(DISCOVERY, true, null);
        flags.updateGlobal(DISCOVERY, false, null);
        fixtures.transitions().forEach(row -> walker.apply(((Number) row.get("id")).longValue(), budget()));

        assertThat(fixtures.cancelledScans(acme)).isEqualTo(3);
        verify(publisher, times(1)).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), anyString(), anyString(), any(),
                anyString());
    }

    @Test
    void aSupersededRowTakenOverByTheBackstopHasNoEffect() {
        long acme = fixtures.organization("acme", "B2B", 3);

        flags.updateGlobal(DISCOVERY, false, null);
        flags.updateGlobal(DISCOVERY, true, null);
        fixtures.ageTransitions();
        backstop.applyStalledTransitions();

        assertThat(fixtures.runningScans(acme)).isEqualTo(3);
        assertThat(fixtures.transitions()).extracting(row -> row.get("status"))
                .containsExactly("SUPERSEDED", "COMPLETE");
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void aGlobalWalkInterruptedByARestartContinuesFromItsSavedCursorAndCompletes() {
        long[] orgs = new long[5];
        for (int i = 0; i < orgs.length; i++) {
            orgs[i] = fixtures.organization("org" + i, "B2B", 1);
        }
        flags.updateGlobal(DISCOVERY, false, null);
        long transition = fixtures.newestTransitionId();

        walker.apply(transition, SweepBudget.of(2, Duration.ofMinutes(1)));
        assertThat(fixtures.cancelledScans(orgs[1])).isOne();
        assertThat(fixtures.runningScans(orgs[2])).as("the budget stopped the walk").isOne();
        assertThat(jdbc.queryForObject("SELECT cursor_organization_id FROM feature_lifecycle_transition WHERE id = ?",
                Long.class, transition)).isEqualTo(orgs[1]);

        // A new pod: nothing in memory, the walk reads its cursor from the row.
        walker.apply(transition, budget());

        for (long org : orgs) {
            assertThat(fixtures.cancelledScans(org)).isOne();
        }
        assertThat(fixtures.transitions()).extracting(row -> row.get("status")).containsExactly("COMPLETE");
        verify(publisher, times(5)).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), anyString(), anyString(), any(),
                anyString());
    }

    @Test
    void theBackstopRecoversALostAfterCommitRunAndEmailsExactlyOnce() {
        long acme = fixtures.organization("acme", "B2B", 3);
        flags.upsertOrgOverrideAsAdmin(acme, DISCOVERY, false, "abuse");

        fixtures.ageTransitions();
        backstop.applyStalledTransitions();
        backstop.applyStalledTransitions();

        assertThat(fixtures.cancelledScans(acme)).isEqualTo(3);
        verify(publisher, times(1)).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), eq(String.valueOf(acme)),
                anyString(), any(), eq(acme + ":" + DISCOVERY + ":PAUSED:1"));
        assertThat(fixtures.transitions()).extracting(row -> row.get("status")).containsExactly("COMPLETE");
    }

    @Test
    void concurrentForcedWritesOfOneFeatureSerializeSoTheirIdsCommitInOrder() throws Exception {
        long first = fixtures.organization("first", "B2B", 1);
        long second = fixtures.organization("second", "B2B", 1);
        TransactionTemplate inTransaction = new TransactionTemplate(transactionManager);
        CountDownLatch firstRecorded = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        // Its own threads: the common pool can have a single worker on a small runner, and the first
        // write holds one on purpose, which would leave the second write queued instead of waiting.
        ExecutorService writers = Executors.newFixedThreadPool(2);
        try {
            CompletableFuture<Void> firstWrite = CompletableFuture.runAsync(() -> inTransaction.executeWithoutResult(tx -> {
                flags.upsertOrgOverrideAsAdmin(first, DISCOVERY, false, null);
                firstRecorded.countDown();
                awaitQuietly(releaseFirst);
            }), writers);
            assertThat(firstRecorded.await(10, TimeUnit.SECONDS)).isTrue();
            // Different organizations: no flag row is shared, only the feature's forced-transition lock.
            CompletableFuture<Void> secondWrite = CompletableFuture.runAsync(() -> inTransaction.executeWithoutResult(
                    tx -> flags.upsertOrgOverrideAsAdmin(second, DISCOVERY, false, null)), writers);

            try {
                awaitOneWaitingAdvisoryLock();
                assertThat(secondWrite).isNotDone();
                assertThat(fixtures.transitions()).as("neither write has committed").isEmpty();
            } finally {
                releaseFirst.countDown();
            }
            firstWrite.get(10, TimeUnit.SECONDS);
            secondWrite.get(10, TimeUnit.SECONDS);
        } finally {
            writers.shutdown();
            assertThat(writers.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }

        assertThat(jdbc.queryForList("SELECT organization_id FROM feature_lifecycle_transition ORDER BY id",
                Long.class)).as("commit order is id order").containsExactly(first, second);
    }

    private void awaitOneWaitingAdvisoryLock() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (jdbc.queryForObject("SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
                Integer.class) != 1) {
            assertThat(System.nanoTime()).as("the second write waits on the advisory lock").isLessThan(deadline);
            Thread.sleep(20);
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    private static SweepBudget budget() {
        return SweepBudget.of(1000, Duration.ofMinutes(1));
    }
}
