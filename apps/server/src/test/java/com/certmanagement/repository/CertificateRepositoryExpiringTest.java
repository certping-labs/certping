// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.repository.CertificateRepository.ExpiringCertificateRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DataJpa coverage for {@link CertificateRepository#findExpiringBetween}.
 *
 * <p>Time zone determinism. The app pins {@code PostgreSQLDialect}, which binds the
 * {@code OffsetDateTime} bounds with {@code setTimestamp(ts, UTC calendar)}. pgjdbc sends that
 * value with a {@code +00} offset, so production compares instants correctly. H2 instead receives
 * an offset-less {@code TIMESTAMP} and, to compare it with the {@code TIMESTAMP WITH TIME ZONE}
 * column, applies its session time zone. That zone defaults to the JVM zone H2 cached the first
 * time it was used in the fork. Before this fix {@code Replace.ANY} also swapped in a random
 * embedded H2 URL, so the URL settings below were ignored and the bounds moved by the JVM offset
 * (IST dropped "at-to", America/Los_Angeles dropped "at-from"). {@code Replace.NONE} keeps this
 * URL, and {@code TIME ZONE=UTC} pins the H2 session zone, so the result no longer depends on the
 * JVM zone or on which test used H2 first.
 */
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.NONE)
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:cert_expiring;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE;TIME ZONE=UTC",
        "spring.jpa.properties.hibernate.jdbc.time_zone=UTC"
})
class CertificateRepositoryExpiringTest {

    private static final long ORG = 1L;
    private static final long OTHER_ORG = 2L;

    // Fixed instants: nothing here reads the wall clock.
    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 9, 22, 12, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime TO = OffsetDateTime.of(2026, 9, 29, 12, 0, 0, 0, ZoneOffset.UTC);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private long certificateIdSeq = 1L;

    @BeforeEach
    void setUpSchema() {
        jdbcTemplate.execute("drop table if exists certificates");
        jdbcTemplate.execute("drop table if exists user_domain_certificate");
        jdbcTemplate.execute("""
                create table user_domain_certificate (
                    id bigint primary key,
                    organization_id bigint not null,
                    domain varchar(255) not null,
                    user_id int,
                    is_deleted boolean not null default false,
                    deleted_at timestamp with time zone,
                    created timestamp with time zone not null,
                    updated timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table certificates (
                    id bigint primary key,
                    certificate_xref varchar(100) not null unique,
                    user_domain_cert_id bigint not null,
                    wildcard boolean not null default false,
                    san boolean not null default false,
                    san_domains varchar(255) array,
                    ca_provider varchar(50) not null,
                    requested_validity_days int,
                    status varchar(50) not null,
                    cert_secret_handle varchar(500),
                    target_resource_id varchar(1000),
                    acme_account_handle varchar(500),
                    ca_credential_handle varchar(500),
                    issuer varchar(500),
                    serial_number varchar(100),
                    fingerprint_sha256 varchar(200),
                    valid_from timestamp with time zone,
                    valid_to timestamp with time zone,
                    signature_algorithm varchar(100),
                    public_key_algorithm varchar(50),
                    key_size int,
                    cert_type varchar(20),
                    last_error_code varchar(100),
                    last_error_message text,
                    last_error_at timestamp with time zone,
                    correlation_id varchar(100),
                    last_alerted_at timestamp with time zone,
                    expiry_alert_threshold_days integer,
                    order_id varchar(64),
                    special_certificate_type varchar(50),
                    key_custody varchar(20) not null default 'PLATFORM_HELD',
                    csr_pem text,
                    ca_account_source varchar(20),
                    ca_order_cost numeric(10,2),
                    ca_order_currency varchar(3),
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null,
                    deleted_at timestamp with time zone
                )
                """);
        insertUdc(10, ORG, "a.example.com", false);
        insertUdc(11, ORG, "b.example.com", false);
        insertUdc(12, ORG, "deleted-udc.example.com", true);
        insertUdc(20, OTHER_ORG, "other.example.com", false);
    }

    @Test
    void findExpiringBetween_filtersAndPagesStableOnTiedValidTo() {
        OffsetDateTime soon = OffsetDateTime.of(2026, 9, 24, 12, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime tied = OffsetDateTime.of(2026, 9, 26, 12, 0, 0, 0, ZoneOffset.UTC);

        saveCert("in-window-soon", 10, "ACTIVE", soon, null);
        // Same validTo — lower id must sort first (ORDER BY validTo, id)
        saveCert("tie-a", 10, "ACTIVE", tied, null);
        saveCert("tie-b", 11, "ACTIVE", tied, null);

        saveCert("expired-before", 10, "ACTIVE",
                OffsetDateTime.of(2026, 9, 10, 12, 0, 0, 0, ZoneOffset.UTC), null);
        saveCert("after-window", 10, "ACTIVE",
                OffsetDateTime.of(2026, 10, 10, 12, 0, 0, 0, ZoneOffset.UTC), null);
        saveCert("renewing", 10, "RENEWING", soon.plusDays(1), null);
        saveCert("soft-deleted-cert", 10, "ACTIVE", soon.plusDays(1),
                OffsetDateTime.of(2026, 9, 1, 0, 0, 0, 0, ZoneOffset.UTC));
        saveCert("foreign-org", 20, "ACTIVE", soon.plusDays(1), null);
        saveCert("null-valid-to", 10, "ACTIVE", null, null);
        // Soft-deleted UDC must not leak into results
        saveCert("on-deleted-udc", 12, "ACTIVE", soon.plusDays(1), null);

        Slice<ExpiringCertificateRow> page0 = certificateRepository.findExpiringBetween(
                ORG, FROM, TO, PageRequest.of(0, 2));
        assertThat(page0.getContent()).extracting(ExpiringCertificateRow::getCertificateXref)
                .containsExactly("in-window-soon", "tie-a");
        assertThat(page0.hasNext()).isTrue();

        Slice<ExpiringCertificateRow> page1 = certificateRepository.findExpiringBetween(
                ORG, FROM, TO, PageRequest.of(1, 2));
        assertThat(page1.getContent()).extracting(ExpiringCertificateRow::getCertificateXref)
                .containsExactly("tie-b");
        assertThat(page1.getContent().get(0).getDomain()).isEqualTo("b.example.com");
        assertThat(page1.hasNext()).isFalse();
    }

    @Test
    void findExpiringBetween_includesInclusiveFromAndToBounds() {
        // Rows exactly on FROM and TO: both bounds of the query are inclusive.
        saveCert("at-from", 10, "ACTIVE", FROM, null);
        saveCert("at-to", 11, "ACTIVE", TO, null);
        // One second outside each bound: excluded. Also catches any zone shift of the bounds.
        saveCert("just-before-from", 10, "ACTIVE", FROM.minusSeconds(1), null);
        saveCert("just-after-to", 11, "ACTIVE", TO.plusSeconds(1), null);

        Slice<ExpiringCertificateRow> slice = certificateRepository.findExpiringBetween(
                ORG, FROM, TO, PageRequest.of(0, 10));

        assertThat(slice.getContent()).extracting(ExpiringCertificateRow::getCertificateXref)
                .containsExactly("at-from", "at-to");
        assertThat(certificateRepository.countExpiringBetween(ORG, FROM, TO)).isEqualTo(2);
    }


    private void insertUdc(long id, long organizationId, String domain, boolean deleted) {
        jdbcTemplate.update("""
                insert into user_domain_certificate
                    (id, organization_id, domain, is_deleted, created, updated)
                values (?, ?, ?, ?,
                    timestamp with time zone '2026-01-01 00:00:00Z',
                    timestamp with time zone '2026-01-01 00:00:00Z')
                """, id, organizationId, domain, deleted);
    }

    private void saveCert(String xref, long userDomainCertId, String status,
                          OffsetDateTime validTo, OffsetDateTime deletedAt) {
        long id = certificateIdSeq++;
        jdbcTemplate.update("""
                insert into certificates (
                    id, certificate_xref, user_domain_cert_id, wildcard, san, ca_provider, status,
                    valid_to, created_at, updated_at, deleted_at)
                values (?, ?, ?, false, false, 'LETS_ENCRYPT', ?, ?,
                    timestamp with time zone '2026-01-01 00:00:00Z',
                    timestamp with time zone '2026-01-01 00:00:00Z', ?)
                """, id, xref, userDomainCertId, status, validTo, deletedAt);
    }
}
