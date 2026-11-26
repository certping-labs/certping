// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertificateEntity;
import jakarta.persistence.EntityManager;
import org.hibernate.Hibernate;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.transaction.TestTransaction;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code CertificateEntity.userDomainCert} is lazy. These pin what that must not change: the
 * agent-result worker reads domain and organization off certificates it loaded outside any
 * session, and certificates whose UDC was soft-deleted read as having none instead of throwing.
 */
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.ANY)
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:cert_udc_fetch;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "spring.jpa.properties.hibernate.generate_statistics=true"
})
class CertificateUserDomainCertFetchTest {

    private static final long ORG = 1L;
    private static final long LIVE_UDC = 10L;
    private static final long DELETED_UDC = 12L;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManager em;

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
        insertUdc(LIVE_UDC, "a.example.com", false);
        insertUdc(11, "b.example.com", false);
        insertUdc(DELETED_UDC, "gone.example.com", true);
        saveCert("live", LIVE_UDC, "ACTIVE", null);
        saveCert("orphan", DELETED_UDC, "ACTIVE", null);
        em.clear();
    }

    @Test
    void theConsumersFinders_returnTheDomainReadableAfterTheSessionIsGone() {
        saveCert("akamai", LIVE_UDC, "ACTIVE", "AKAMAI");
        List<Supplier<CertificateEntity>> finders = List.of(
                () -> certificateRepository.findByCertificateXref("live").orElseThrow(),
                () -> certificateRepository.findByCertificateXrefAndOrganizationId("live", ORG).orElseThrow(),
                () -> certificateRepository
                        .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(LIVE_UDC, "ACTIVE")
                        .orElseThrow(),
                () -> certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(LIVE_UDC, "AKAMAI", "ACTIVE")
                        .orElseThrow(),
                () -> certificateRepository.findByOrganizationIdAndCertificateXrefIn(ORG, List.of("live")).get(0));

        for (Supplier<CertificateEntity> finder : finders) {
            em.clear();
            CertificateEntity cert = finder.get();
            em.clear();

            assertThat(Hibernate.isInitialized(cert.getUserDomainCert())).isTrue();
            assertThat(cert.getDomain()).isEqualTo("a.example.com");
            assertThat(cert.getOrganizationId()).isEqualTo(ORG);
        }
    }

    @Test
    void aCertificateOfADeletedUdc_hasNoDomain_whetherFetchedOrProxied() {
        CertificateEntity fetched = certificateRepository.findByCertificateXref("orphan").orElseThrow();
        assertThat(fetched.getDomain()).isNull();
        assertThat(fetched.getOrganizationId()).isNull();
        em.clear();

        CertificateEntity proxied = certificateRepository.findById(idOf("orphan")).orElseThrow();
        assertThat(Hibernate.isInitialized(proxied.getUserDomainCert())).isFalse();
        assertThat(proxied.getDomain()).isNull();
        assertThat(proxied.getOrganizationId()).isNull();
        // Swallowing the miss must not doom the caller's transaction.
        TestTransaction.flagForCommit();
        TestTransaction.end();
    }

    @Test
    void aProxiedCertificateOfALiveUdc_loadsItOnFirstUse() {
        CertificateEntity proxied = certificateRepository.findById(idOf("live")).orElseThrow();

        assertThat(Hibernate.isInitialized(proxied.getUserDomainCert())).isFalse();
        assertThat(proxied.getDomain()).isEqualTo("a.example.com");
    }

    @Test
    void aPageOfCertificates_isOneQuery_withNoLoadPerDomain() {
        saveCert("second", 11, "ACTIVE", null);
        Statistics statistics = em.getEntityManagerFactory().unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        Page<CertificateEntity> page = certificateRepository.findLatestByOrganizationAndFilters(
                ORG, null, null, PageRequest.of(0, 10));
        List<String> domains = page.map(CertificateEntity::getDomain).getContent();

        // The orphan's user-domain-cert is soft-deleted; Hibernate 7 applies that entity's
        // @SQLRestriction to the explicit join too, so the orphan is not part of the listing.
        assertThat(page.getTotalElements()).isEqualTo(2);
        assertThat(domains).containsExactlyInAnyOrder("a.example.com", "b.example.com");
        // The page holds every row, so Spring Data skips the count.
        assertThat(statistics.getQueryExecutionCount()).isEqualTo(1);
        assertThat(statistics.getEntityFetchCount()).isZero();
    }

    @Test
    void aPageOfOneDomainsHistory_isOneQuery_withNoLoadOfTheDomain() {
        saveCert("renewed", LIVE_UDC, "ACTIVE", null);
        Statistics statistics = em.getEntityManagerFactory().unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        Page<CertificateEntity> page = certificateRepository.findHistoryByOrganizationAndUserDomainCertId(
                ORG, LIVE_UDC, PageRequest.of(0, 10));
        List<String> domains = page.map(CertificateEntity::getDomain).getContent();

        assertThat(domains).containsExactly("a.example.com", "a.example.com");
        assertThat(statistics.getQueryExecutionCount()).isEqualTo(1);
        assertThat(statistics.getEntityFetchCount()).isZero();
    }

    private long idOf(String xref) {
        return jdbcTemplate.queryForObject("select id from certificates where certificate_xref = ?", Long.class, xref);
    }

    private void insertUdc(long id, String domain, boolean deleted) {
        jdbcTemplate.update("""
                insert into user_domain_certificate
                    (id, organization_id, domain, is_deleted, created, updated)
                values (?, ?, ?, ?,
                    timestamp with time zone '2026-01-01 00:00:00Z',
                    timestamp with time zone '2026-01-01 00:00:00Z')
                """, id, ORG, domain, deleted);
    }

    private void saveCert(String xref, long userDomainCertId, String status, String specialType) {
        jdbcTemplate.update("""
                insert into certificates (
                    id, certificate_xref, user_domain_cert_id, wildcard, san, ca_provider, status,
                    special_certificate_type, created_at, updated_at)
                values (?, ?, ?, false, false, 'LETS_ENCRYPT', ?, ?,
                    timestamp with time zone '2026-01-01 00:00:00Z',
                    timestamp with time zone '2026-01-01 00:00:00Z')
                """, certificateIdSeq++, xref, userDomainCertId, status, specialType);
    }
}
