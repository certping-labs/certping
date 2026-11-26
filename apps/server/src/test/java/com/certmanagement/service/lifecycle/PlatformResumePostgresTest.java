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
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.certmanagement.service.lifecycle.LifecycleFixtures.DISCOVERY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

/**
 * Platform resumes on real PostgreSQL with the real resolver: a RESUMED email goes out whenever the
 * pause it ends was claimed for emailing, even with nothing resumed (a cancelled discovery scan), and
 * even while the PAUSED publish is still in flight; a baseline pause, never emailed, resumes in silence.
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
class PlatformResumePostgresTest {

    /** audit_events is not under test here. */
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
    @Autowired private FeatureLifecycleReconciler reconciler;
    @Autowired private FeatureLifecycleBackstopJob backstop;
    @Autowired private JdbcTemplate jdbc;

    private LifecycleFixtures fixtures;

    @BeforeEach
    void seed() {
        fixtures = new LifecycleFixtures(jdbc);
        fixtures.reset();
        reset(publisher);
        reset(publisher);
    }

    @Test
    void aForcedPauseAndResumeEmailOnceEach() {
        long acme = fixtures.organization("acme", "B2B", 3);

        switchGlobal(DISCOVERY, false);
        reconciler.reconcileOrganization(DISCOVERY, acme);
        switchGlobal(DISCOVERY, true);
        reconciler.reconcileOrganization(DISCOVERY, acme);

        assertThat(fixtures.cancelledScans(acme)).as("a cancelled scan is not restarted").isEqualTo(3);
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), eq(String.valueOf(acme)), anyString(), any(),
                eq(acme + ":" + DISCOVERY + ":PAUSED:1"));
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_RESUMED"), eq(String.valueOf(acme)), anyString(), any(),
                eq(acme + ":" + DISCOVERY + ":RESUMED:2"));
    }

    @Test
    void aDiscoveryPauseAndResumeSendBothEmailsThoughNoScanRestarts() {
        long acme = fixtures.organization("acme", "B2B", 0);
        fixtures.runningScan(acme, "req-run");

        switchGlobal("DISCOVERY", false);
        assertThat(jdbc.queryForObject("SELECT status FROM discovery_scan", String.class)).isEqualTo("CANCELLED");
        switchGlobal("DISCOVERY", true);

        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), eq(String.valueOf(acme)), anyString(), any(),
                anyString());
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_RESUMED"), eq(String.valueOf(acme)), anyString(),
                argThat(fields -> java.util.List.of().equals(fields.get("items"))), anyString());
        assertThat(jdbc.queryForObject("SELECT status FROM discovery_scan", String.class))
                .as("a cancelled scan is not restarted").isEqualTo("CANCELLED");
    }

    @Test
    void aBaselinePausedOrganizationResumesWithoutAnyEmail() {
        long acme = fixtures.organization("acme", "B2B", 2);
        fixtures.orgOverride(acme, DISCOVERY, false, false);
        fixtures.switchBaseline(true);
        backstop.reconcileAll();
        assertThat(fixtures.cancelledScans(acme)).isEqualTo(2);

        flags.upsertOrgOverride(acme, DISCOVERY, true, "back on");
        reconciler.reconcileOrganization(DISCOVERY, acme);

        assertThat(fixtures.cancelledScans(acme)).isEqualTo(2);
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void aResumeWhileThePausedEmailIsBeingPublishedStillSendsTheResumedEmail() throws Exception {
        long acme = fixtures.organization("acme", "B2B", 2);
        ExecutorService otherPod = Executors.newSingleThreadExecutor();
        try {
            doAnswer(call -> {
                otherPod.submit(() -> switchGlobal(DISCOVERY, true)).get(30, TimeUnit.SECONDS);
                return null;
            }).when(publisher).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), anyString(), anyString(), any(),
                    anyString());

            switchGlobal(DISCOVERY, false);
        } finally {
            otherPod.shutdownNow();
        }

        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_RESUMED"), eq(String.valueOf(acme)), anyString(), any(),
                eq(acme + ":" + DISCOVERY + ":RESUMED:2"));
        assertThat(fixtures.cancelledScans(acme)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT notified_seq FROM feature_lifecycle_state WHERE organization_id = ?",
                Long.class, acme)).isEqualTo(2);
    }

    /** A super admin's global write, then its after-commit walk. */
    private void switchGlobal(String featureKey, boolean enabled) {
        long before = fixtures.newestTransitionId();
        flags.updateGlobal(featureKey, enabled, null);
        long recorded = fixtures.newestTransitionId();
        if (recorded > before) {
            walker.apply(recorded, budget());
        }
    }

    private static SweepBudget budget() {
        return SweepBudget.of(1000, Duration.ofMinutes(1));
    }
}
