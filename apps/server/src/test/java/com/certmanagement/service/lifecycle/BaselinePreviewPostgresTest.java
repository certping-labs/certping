// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.config.ClockConfig;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.lifecycle.AccessLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.DiscoveryLifecycleRepository;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
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
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.HashMap;
import java.util.Map;

import static com.certmanagement.service.lifecycle.LifecycleFixtures.DISCOVERY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

/**
 * The baseline preview on real PostgreSQL with the real resolver: over a seeded mix of
 * causes (org-type default, a super admin's locked override, the category, the global switch), the
 * per-cause counts the preview shows are exactly what the baseline then pauses once the
 * {@code FEATURE_LIFECYCLE_RECONCILE} switch is on, each audited as system:baseline with its cause.
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
        ForcedTransitionWalker.class, FeatureLifecycleSweeper.class, BaselineClassifier.class, BaselinePreviewService.class,
        FeatureLifecycleBackstopJob.class, SchedulerExecutionPolicy.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class BaselinePreviewPostgresTest {

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

    @Autowired private BaselinePreviewService preview;
    @Autowired private FeatureLifecycleBackstopJob backstop;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbc;

    private static final java.util.regex.Pattern PAUSED = java.util.regex.Pattern.compile("^Paused (\\d+) record");

    private LifecycleFixtures fixtures;

    @BeforeEach
    void seed() {
        fixtures = new LifecycleFixtures(jdbc);
        fixtures.reset();
        reset(publisher);
    }

    @Test
    void thePreviewShowsPerCauseExactlyWhatTheBaselineThenPauses() {
        fixtures.orgTypeDefault("B2B", DISCOVERY, false);
        long typeOff = fixtures.organization("typeoff", "B2B", 2);
        long lockedOff = fixtures.organization("lockedoff", "B2B", 1);
        fixtures.orgOverride(lockedOff, DISCOVERY, false, true);
        long lockedOn = fixtures.organization("lockedon", "B2B", 1);
        fixtures.orgOverride(lockedOn, DISCOVERY, true, true);

        Map<String, Tally> previewed = previewed(preview.preview());

        assertThat(previewed).containsOnly(
                entry(DISCOVERY + "/ORG_TYPE", new Tally(1, 2)),
                entry(DISCOVERY + "/ORG_OVERRIDE", new Tally(1, 1)));
        assertThat(fixtures.cancelledScans(typeOff)).as("a preview changes nothing").isZero();

        fixtures.switchBaseline(true);
        backstop.reconcileAll();

        assertThat(baselinePaused()).isEqualTo(previewed);
        assertThat(fixtures.runningScans(lockedOn)).isOne();
        verify(publisher, never()).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void withNothingOffThePreviewIsEmptyPerFeature() {
        fixtures.organization("acme", "B2B", 2);

        BaselinePreviewResponse response = preview.preview();

        assertThat(response.features()).extracting(BaselinePreviewResponse.FeaturePreview::featureKey)
                .contains(DISCOVERY);
        assertThat(response.features()).allSatisfy(feature -> assertThat(feature.records()).isZero());
    }

    private static Map<String, Tally> previewed(BaselinePreviewResponse response) {
        Map<String, Tally> tallies = new HashMap<>();
        for (BaselinePreviewResponse.FeaturePreview feature : response.features()) {
            for (BaselinePreviewResponse.CausePreview cause : feature.byCause()) {
                tallies.put(feature.featureKey() + "/" + cause.cause(), new Tally(cause.organizations(),
                        cause.records()));
            }
        }
        return tallies;
    }

    /** Per feature and cause, the organizations and records the baseline audit rows say it paused. */
    private Map<String, Tally> baselinePaused() {
        ArgumentCaptor<com.certmanagement.audit.AuditEventRow> rows =
                ArgumentCaptor.forClass(com.certmanagement.audit.AuditEventRow.class);
        verify(auditRecorder, org.mockito.Mockito.atLeastOnce()).record(rows.capture());
        Map<String, Tally> tallies = new HashMap<>();
        for (com.certmanagement.audit.AuditEventRow row : rows.getAllValues()) {
            if (!"feature.paused".equals(row.event())) {
                continue;
            }
            assertThat(row.actorJob()).isEqualTo("feature-lifecycle-reconcile");
            java.util.regex.Matcher paused = PAUSED.matcher(row.summary());
            assertThat(paused.find()).as(row.summary()).isTrue();
            tallies.merge(row.resourceRef() + "/" + row.details().attributes().get("cause"),
                    new Tally(1, Long.parseLong(paused.group(1))),
                    (a, b) -> new Tally(a.organizations() + b.organizations(), a.records() + b.records()));
        }
        return tallies;
    }

    private record Tally(long organizations, long records) {
    }
}
