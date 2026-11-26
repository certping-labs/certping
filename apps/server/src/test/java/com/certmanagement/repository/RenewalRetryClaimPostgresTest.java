// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The retry-renewals claim and the failure count on real PostgreSQL: which schedules the claim takes, that it uses
 * idx_renewal_schedule_retry_due, that a repaired credential starts the count again, and that a manual renewal and
 * the retry job never both start a renewal.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RenewalRetryClaimPostgresTest {

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

    @Autowired private RenewalScheduleRepository schedules;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;

    @Autowired private CertificateRepository certificates;

    private long org;
    private long udc;
    private long config;

    @BeforeEach
    void seed() {
        jdbc.execute("TRUNCATE renewal_schedule, certificates, domain_credential_config, user_domain_certificate CASCADE");
        String slug = "org-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id, dns_config,"
                + " deployment_targets) VALUES (?, '{\"example.com\": \"cred-dns\"}'::jsonb, '[]'::jsonb)"
                + " RETURNING id", Long.class, udc);
    }

    @Test
    void existingSchedulesStartWithNoFailures() {
        String xref = schedule("ACTIVE", "SUCCESS", true, false, "NULL");

        assertThat(failures(xref)).isZero();
    }

    @Test
    void aDueFailureIsClaimed() {
        String xref = schedule("ACTIVE", "FAILED", true, false, "NOW() - INTERVAL '1 minute'");

        assertThat(claim()).contains(xref);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "not due yet          | ACTIVE   | FAILED       | true  | false | NOW() + INTERVAL '5 minutes'",
            "parked               | ACTIVE   | FAILED       | true  | false | NULL",
            "first attempt        | ACTIVE   | NULL         | true  | false | NULL",
            "renewed              | ACTIVE   | SUCCESS      | true  | false | NOW() - INTERVAL '1 minute'",
            "feature hold         | ACTIVE   | FEATURE_HOLD | true  | false | NOW() - INTERVAL '1 minute'",
            "in flight            | ACTIVE   | IN_PROGRESS  | true  | false | NOW() - INTERVAL '1 minute'",
            "disabled             | ACTIVE   | FAILED       | false | false | NOW() - INTERVAL '1 minute'",
            "deleted              | ACTIVE   | FAILED       | true  | true  | NOW() - INTERVAL '1 minute'",
            "certificate renewing | RENEWING | FAILED       | true  | false | NOW() - INTERVAL '1 minute'"})
    void onlyDueFailuresOfLiveEnabledSchedulesAreClaimed(String reason, String certStatus, String scheduleStatus,
                                                          boolean enabled, boolean deleted, String nextAttemptAt) {
        schedule(certStatus, "NULL".equals(scheduleStatus) ? null : scheduleStatus, enabled, deleted, nextAttemptAt);

        assertThat(claim()).as(reason).isEmpty();
    }

    @Test
    void theClaimUsesTheRetryIndex() {
        String plan = transactions.execute(status -> {
            jdbc.execute("SET LOCAL enable_seqscan = off");
            List<String> lines = jdbc.queryForList("EXPLAIN SELECT s.* FROM renewal_schedule s"
                    + " JOIN certificates c ON c.certificate_xref = s.certificate_xref"
                    + " WHERE s.last_renewal_status = 'FAILED' AND s.enabled AND NOT s.is_deleted"
                    + " AND s.next_attempt_at <= NOW() AND s.renewal_eligible_at <= NOW()"
                    + " AND c.status <> 'RENEWING' ORDER BY s.next_attempt_at ASC"
                    + " FOR UPDATE SKIP LOCKED LIMIT 1", String.class);
            return String.join("\n", lines);
        });

        assertThat(plan).contains("idx_renewal_schedule_retry_due");
    }

    @Test
    void aRepairedCredentialRearmsAParkedFailureAndStartsItsCountAgain() {
        String xref = schedule("ACTIVE", "FAILED", true, false, "NULL");
        jdbc.update("UPDATE renewal_schedule SET consecutive_failures = 4 WHERE certificate_xref = ?", xref);

        transactions.executeWithoutResult(status -> schedules.rearmParkedFailuresByDomainCredentialConfigId(config));

        assertThat(failures(xref)).isZero();
        assertThat(claim()).contains(xref);
    }

    @Test
    void aRepairedSharedCredentialStartsTheCountAgain() {
        String xref = schedule("ACTIVE", "FAILED", true, false, "NULL");
        jdbc.update("UPDATE renewal_schedule SET consecutive_failures = 2 WHERE certificate_xref = ?", xref);

        transactions.executeWithoutResult(status -> schedules.rearmParkedFailuresByDnsCredentialXref("cred-dns"));

        assertThat(failures(xref)).isZero();
    }

    @Test
    void aNegativeCountIsRefused() {
        String xref = schedule("ACTIVE", "FAILED", true, false, "NULL");

        assertThatThrownBy(() -> jdbc.update(
                        "UPDATE renewal_schedule SET consecutive_failures = -1 WHERE certificate_xref = ?", xref))
                .hasMessageContaining("chk_renewal_schedule_consecutive_failures");
    }

    @Test
    void aManualRenewalAndTheRetryJobNeverBothStartARenewal() throws Exception {
        String xref = schedule("ACTIVE", "FAILED", true, false, "NOW() - INTERVAL '1 minute'");
        CountDownLatch claimed = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        CompletableFuture<String> retryJob = CompletableFuture.supplyAsync(() -> transactions.execute(status -> {
            String claimedXref = schedules.claimOneDueRetry(databaseNow()).orElseThrow()
                    .getCertificateXref();
            certificates.updateStatus(claimedXref, "RENEWING");
            claimed.countDown();
            await(release);
            return claimedXref;
        }));
        assertThat(claimed.await(30, TimeUnit.SECONDS)).isTrue();
        CompletableFuture<Integer> manual = CompletableFuture.supplyAsync(() -> transactions.execute(status ->
                certificates.tryMarkRenewing(xref, org, OffsetDateTime.now(ZoneOffset.UTC))));
        release.countDown();

        assertThat(retryJob.get(30, TimeUnit.SECONDS)).isEqualTo(xref);
        assertThat(manual.get(30, TimeUnit.SECONDS)).as("the manual renewal finds the job's RENEWING").isZero();
        assertThat(claim()).as("and the retry claim skips a renewing certificate").isEmpty();
    }

    @Test
    void twoManualRenewalsAtOnceStartOneRenewal() throws Exception {
        String xref = schedule("ACTIVE", "SUCCESS", true, false, "NULL");

        List<CompletableFuture<Integer>> attempts = List.of(
                CompletableFuture.supplyAsync(() -> transactions.execute(status ->
                        certificates.tryMarkRenewing(xref, org, OffsetDateTime.now(ZoneOffset.UTC)))),
                CompletableFuture.supplyAsync(() -> transactions.execute(status ->
                        certificates.tryMarkRenewing(xref, org, OffsetDateTime.now(ZoneOffset.UTC)))));

        int moved = 0;
        for (CompletableFuture<Integer> attempt : attempts) {
            moved += attempt.get(30, TimeUnit.SECONDS);
        }
        assertThat(moved).isEqualTo(1);
    }

    @Test
    void anotherOrganizationCannotStartARenewal() {
        String xref = schedule("ACTIVE", "SUCCESS", true, false, "NULL");

        Integer moved = transactions.execute(status ->
                certificates.tryMarkRenewing(xref, org + 1, OffsetDateTime.now(ZoneOffset.UTC)));

        assertThat(moved).isZero();
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private Optional<String> claim() {
        return transactions.execute(status -> schedules.claimOneDueRetry(databaseNow())
                .map(s -> s.getCertificateXref()));
    }

    /**
     * The database's clock. Schedules are rearmed and made due with the database's NOW(), so the claim is
     * asked with that clock too: the JVM's clock can run behind the container's by a few milliseconds, which
     * made a just-rearmed schedule look not yet due.
     */
    private OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    private String schedule(String certStatus, String scheduleStatus, boolean enabled, boolean deleted,
                            String nextAttemptAt) {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', ?, NOW() + INTERVAL '20 days')", xref, udc, certStatus);
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled, is_deleted, last_renewal_status, next_attempt_at)"
                + " VALUES (?, ?, NOW() + INTERVAL '20 days', NOW() - INTERVAL '10 days', 'LETS_ENCRYPT', ?, ?, ?, "
                + nextAttemptAt + ")", xref, config, enabled, deleted, scheduleStatus);
        return xref;
    }

    private int failures(String xref) {
        return jdbc.queryForObject("SELECT consecutive_failures FROM renewal_schedule WHERE certificate_xref = ?",
                Integer.class, xref);
    }
}
