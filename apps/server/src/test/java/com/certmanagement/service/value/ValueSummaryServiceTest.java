// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.value;

import com.certmanagement.dto.value.ValueSummaryDto;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The value summary on real PostgreSQL: an expired certificate is not "expiring
 * soon", a renewal counts as before expiry only when it completed before the replaced certificate's
 * not_after, and "unmanaged" is what the discovery page counts (managed = false, not MISSING).
 */
@Testcontainers(disabledWithoutDocker = true)
class ValueSummaryServiceTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");

    private static JdbcTemplate jdbc;

    private ValueSummaryService service;
    private long org;
    private long udc;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @BeforeEach
    void seed() {
        String slug = "org-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        service = new ValueSummaryService(jdbc, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void anExpiredUnmanagedCertificateIsNotExpiringSoon() {
        discovered(false, "PRESENT", NOW.minus(Duration.ofDays(2)));   // expired
        discovered(false, "PRESENT", NOW.plus(Duration.ofDays(10)));   // expiring soon
        discovered(false, "PRESENT", NOW.plus(Duration.ofDays(29)));   // expiring soon
        discovered(false, "PRESENT", NOW.plus(Duration.ofDays(60)));   // not soon

        ValueSummaryDto summary = service.summarize(org, 365);

        assertThat(summary.unmanagedExpiringSoon()).isEqualTo(2);
        assertThat(summary.unmanagedDiscovered()).isEqualTo(4);
    }

    @Test
    void unmanagedIsWhatTheDiscoveryPageCounts() {
        discovered(false, "PRESENT", NOW.plus(Duration.ofDays(90)));
        discovered(false, "UNKNOWN", NOW.plus(Duration.ofDays(90)));
        discovered(false, "MISSING", NOW.plus(Duration.ofDays(5)));    // gone: not counted
        discovered(true, "PRESENT", NOW.plus(Duration.ofDays(5)));     // managed
        discovered(null, "PRESENT", NOW.plus(Duration.ofDays(5)));     // never matched: not "unmanaged"

        ValueSummaryDto summary = service.summarize(org, 365);

        assertThat(summary.unmanagedDiscovered()).isEqualTo(2);
        assertThat(summary.unmanagedExpiringSoon()).isZero();
    }

    @Test
    void onlyRenewalsCompletedBeforeTheOldNotAfterCountAsBeforeExpiry() {
        renewal(NOW.minus(Duration.ofDays(40)), NOW.minus(Duration.ofDays(45)));  // renewed 5 days early
        renewal(NOW.minus(Duration.ofDays(20)), NOW.minus(Duration.ofDays(21)));  // 1 day early
        renewal(NOW.minus(Duration.ofDays(10)), NOW.minus(Duration.ofDays(3)));   // after it had expired
        renewal(null, NOW.minus(Duration.ofDays(3)));                              // no not_after known

        ValueSummaryDto summary = service.summarize(org, 365);

        assertThat(summary.renewals()).isEqualTo(4);
        assertThat(summary.renewedBeforeExpiry()).isEqualTo(2);
        assertThat(summary.minutesSaved()).isEqualTo(4L * ValueSummaryService.MINUTES_PER_RENEWAL);
    }

    @Test
    void renewalsOutsideTheWindowAreNotCounted() {
        renewal(NOW.minus(Duration.ofDays(20)), NOW.minus(Duration.ofDays(400)));

        ValueSummaryDto summary = service.summarize(org, 365);

        assertThat(summary.renewals()).isZero();
        assertThat(summary.renewedBeforeExpiry()).isZero();
    }

    private void discovered(Boolean managed, String inventoryStatus, Instant notAfter) {
        jdbc.update("INSERT INTO discovered_cert (organization_id, request_id, target_type, resource_id, managed,"
                        + " inventory_status, not_after) VALUES (?, 'req', 'AWS_ACM', ?, ?, ?, ?)",
                org, "arn:aws:acm:us-east-1:1:certificate/" + UUID.randomUUID(), managed, inventoryStatus,
                Timestamp.from(notAfter));
    }

    /** A renewal applied at {@code renewedAt} of a certificate that expired (or expires) at {@code oldNotAfter}. */
    private void renewal(Instant oldNotAfter, Instant renewedAt) {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'RENEW_SUCCESS', ?)", xref, udc,
                oldNotAfter == null ? null : Timestamp.from(oldNotAfter));
        jdbc.update("INSERT INTO certificate_events (certificate_xref, organization_id, event_type, occurred_at)"
                + " VALUES (?, ?, 'RENEWAL_SUCCESS', ?)", xref, org, Timestamp.from(renewedAt));
    }
}
