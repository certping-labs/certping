// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The stalled-renewal sweep on real PostgreSQL: which certificates it claims, what ending an attempt leaves
 * behind, and that the renewal claim then takes the schedule back.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class StalledRenewalRecoveryPostgresTest {

    private static final Duration PAST_HORIZON = AbandonedRenewalCleanup.IN_FLIGHT_HORIZON.plusHours(1);
    private static final Duration INSIDE_HORIZON = AbandonedRenewalCleanup.IN_FLIGHT_HORIZON.minusHours(1);

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

    @Autowired private CertificateRepository certificates;
    @Autowired private RenewalScheduleRepository schedules;
    @Autowired private CertificateEventRepository events;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;

    private StalledRenewalRecoveryService sweep;
    private long udc;
    private long config;

    @BeforeEach
    void seed() {
        jdbc.execute("TRUNCATE renewal_schedule, certificate_events, certificates, domain_credential_config,"
                + " user_domain_certificate CASCADE");
        String slug = "org-" + UUID.randomUUID();
        long org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id, dns_config,"
                + " deployment_targets) VALUES (?, '{\"example.com\": \"cred-dns\"}'::jsonb, '[]'::jsonb)"
                + " RETURNING id", Long.class, udc);
        sweep = new StalledRenewalRecoveryService(certificates, schedules, events,
                new AbandonedRenewalCleanup(certificates, schedules), mock(CertificateAuditRecorder.class),
                new SimpleMeterRegistry());
    }

    @Test
    void anInProgressRenewalPastTheHorizonIsEndedAndItsScheduleIsClaimableAgain() {
        String source = certificate("RENEWING", PAST_HORIZON);
        String draft = certificate("PENDING", PAST_HORIZON);
        schedule(source, true, "IN_PROGRESS");

        assertThat(sweepOnce()).isTrue();

        assertThat(status(source)).isEqualTo("ACTIVE");
        assertThat(status(draft)).isEqualTo("RENEWAL_FAILED");
        assertThat(jdbc.queryForObject("SELECT last_error_code FROM certificates WHERE certificate_xref = ?",
                String.class, draft)).isEqualTo("RENEWAL_RESPONSE_TIMEOUT");
        assertThat(jdbc.queryForObject("SELECT last_renewal_status || ':' || consecutive_failures || ':'"
                + " || (next_attempt_at > NOW() + INTERVAL '14 minutes') FROM renewal_schedule"
                + " WHERE certificate_xref = ?", String.class, source)).isEqualTo("FAILED:1:true");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificate_events WHERE certificate_xref = ?"
                + " AND event_type = 'RENEWAL_FAILED'", Integer.class, source)).isEqualTo(1);
        jdbc.update("UPDATE renewal_schedule SET next_attempt_at = NOW() - INTERVAL '1 minute'"
                + " WHERE certificate_xref = ?", source);
        assertThat(claimSchedule()).as("claimable once its retry is due").contains(source);
        assertThat(sweepOnce()).as("an ended attempt is not claimed again").isFalse();
    }

    @Test
    void aWriteToTheCertificateDuringTheStall_doesNotDelayRecovery() {
        String source = certificate("RENEWING", PAST_HORIZON);
        certificate("PENDING", PAST_HORIZON);
        schedule(source, true, "IN_PROGRESS");
        jdbc.update("UPDATE certificates SET last_alerted_at = NOW(), updated_at = NOW() WHERE certificate_xref = ?",
                source);

        assertThat(sweepOnce()).as("the renewal started when its draft was written").isTrue();
        assertThat(status(source)).isEqualTo("ACTIVE");
    }

    @Test
    void aRenewalInsideTheHorizonIsLeftInFlight() {
        String source = certificate("RENEWING", PAST_HORIZON);
        certificate("PENDING", INSIDE_HORIZON);
        schedule(source, true, "IN_PROGRESS");

        assertThat(sweepOnce()).isFalse();

        assertThat(status(source)).isEqualTo("RENEWING");
        assertThat(claimSchedule()).as("the renewal claim still skips a renewing certificate").isEmpty();
    }

    @Test
    void aManualRenewalOnAHeldScheduleIsEndedAndTheHoldIsKept() {
        String source = certificate("RENEWING", PAST_HORIZON);
        schedule(source, false, "FEATURE_HOLD");

        assertThat(sweepOnce()).isTrue();

        assertThat(status(source)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT enabled || ':' || last_renewal_status || ':' ||"
                + " (next_attempt_at IS NULL) FROM renewal_schedule WHERE certificate_xref = ?", String.class, source))
                .isEqualTo("false:FEATURE_HOLD:true");
    }

    @Test
    void aCertificateSupersededWhileRenewingIsRetiredWithoutBreakingTheSingleActiveRule() {
        String source = certificate("RENEWING", PAST_HORIZON);
        String reissued = certificate("ACTIVE", Duration.ZERO);
        schedule(source, true, "IN_PROGRESS");

        assertThat(sweepOnce()).isTrue();

        assertThat(status(source)).isEqualTo("RENEW_SUCCESS");
        assertThat(status(reissued)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT enabled FROM renewal_schedule WHERE certificate_xref = ?",
                Boolean.class, source)).isFalse();
    }

    @Test
    void twoSweepsNeverClaimTheSameCertificate() throws Exception {
        String first = certificate("RENEWING", PAST_HORIZON.plusHours(1));
        certificate("RENEWING", PAST_HORIZON);
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON);

        CompletableFuture<String> holder = CompletableFuture.supplyAsync(() -> transactions.execute(status -> {
            String claimed = certificates.claimOneStalledRenewal(cutoff).orElseThrow().getCertificateXref();
            held.countDown();
            await(release);
            return claimed;
        }));
        assertThat(held.await(30, TimeUnit.SECONDS)).isTrue();
        String second = transactions.execute(status ->
                certificates.claimOneStalledRenewal(cutoff).map(CertificateEntity::getCertificateXref).orElse(null));
        release.countDown();

        assertThat(holder.get(30, TimeUnit.SECONDS)).isEqualTo(first);
        assertThat(second).isNotNull().isNotEqualTo(first);
    }

    private boolean sweepOnce() {
        return Boolean.TRUE.equals(transactions.execute(status -> sweep.tryProcessOneEligible()));
    }

    private Optional<String> claimSchedule() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        return transactions.execute(status -> schedules.claimOneEligible(now,
                now.minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON)).map(s -> s.getCertificateXref()));
    }

    private String certificate(String status, Duration age) {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to,"
                + " created_at, updated_at) VALUES (?, ?, 'LETS_ENCRYPT', ?, NOW() + INTERVAL '20 days',"
                + " NOW() - ?::interval, NOW() - ?::interval)",
                xref, udc, status, age.toSeconds() + " seconds", age.toSeconds() + " seconds");
        return xref;
    }

    private void schedule(String xref, boolean enabled, String status) {
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled, last_renewal_status) VALUES (?, ?,"
                + " NOW() + INTERVAL '20 days', NOW() - INTERVAL '10 days', 'LETS_ENCRYPT', ?, ?)",
                xref, config, enabled, status);
    }

    private String status(String xref) {
        return jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class, xref);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
