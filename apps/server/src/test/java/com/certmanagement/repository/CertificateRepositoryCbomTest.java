// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.repository.CertificateRepository.CbomCertificateRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.ANY)
class CertificateRepositoryCbomTest {

    private static final long ORG = 1L;
    private static final long OTHER_ORG = 2L;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUpSchema() {
        jdbcTemplate.execute("drop table if exists certificate_crypto_metadata");
        jdbcTemplate.execute("drop table if exists certificates");
        jdbcTemplate.execute("drop table if exists user_domain_certificate");
        jdbcTemplate.execute("""
                create table user_domain_certificate (
                    id bigint primary key,
                    organization_id bigint not null,
                    domain varchar(255) not null,
                    is_deleted boolean not null default false
                )
                """);
        jdbcTemplate.execute("""
                create table certificates (
                    id bigint primary key,
                    certificate_xref varchar(100) not null unique,
                    user_domain_cert_id bigint not null,
                    ca_provider varchar(50) not null,
                    issuer varchar(500),
                    serial_number varchar(100),
                    fingerprint_sha256 varchar(200),
                    valid_from timestamp with time zone,
                    valid_to timestamp with time zone,
                    signature_algorithm varchar(100),
                    public_key_algorithm varchar(50),
                    key_size int,
                    status varchar(50) not null,
                    created_at timestamp with time zone not null,
                    deleted_at timestamp with time zone
                )
                """);
        jdbcTemplate.execute("""
                create table certificate_crypto_metadata (
                    id bigint primary key,
                    certificate_xref varchar(100) not null unique,
                    signature_algorithm_oid varchar(100),
                    subject_dn text,
                    common_name varchar(255),
                    public_key_curve varchar(100),
                    key_usage varchar(255),
                    extended_key_usage text,
                    subject_key_identifier varchar(200),
                    authority_key_identifier varchar(200)
                )
                """);
        jdbcTemplate.update("insert into user_domain_certificate (id, organization_id, domain) values (10, ?, 'a.example.com')", ORG);
        jdbcTemplate.update("insert into user_domain_certificate (id, organization_id, domain) values (11, ?, 'b.example.com')", ORG);
        jdbcTemplate.update("insert into user_domain_certificate (id, organization_id, domain) values (20, ?, 'other.example.com')", OTHER_ORG);
    }

    @Test
    void streamCbomRows_yieldsTheCurrentCertOfEachDomainInIdOrderWithJoinedMetadata() {
        saveCert(3, "third", 10, "RSA", null);
        saveCert(1, "first", 11, "RSA", null);
        saveCert(2, "gone", 11, "RSA", OffsetDateTime.parse("2026-02-01T00:00:00Z"));
        saveCert(4, "foreign", 20, "RSA", null);
        saveCert(5, "superseded", 10, "RSA", null, "RENEW_SUCCESS", "2025-06-01 00:00:00Z");
        saveCert(6, "draft", 10, "RSA", null, "PENDING", "2026-03-01 00:00:00Z");
        jdbcTemplate.update("""
                insert into certificate_crypto_metadata (id, certificate_xref, signature_algorithm_oid, subject_dn,
                    common_name, public_key_curve, key_usage, extended_key_usage, subject_key_identifier,
                    authority_key_identifier)
                values (1, 'first', '1.2.840.113549.1.1.11', 'CN=first.example.com', 'first.example.com', null,
                    'digitalSignature', 'serverAuth', 'SKI', 'AKI')
                """);

        List<CbomCertificateRow> rows;
        try (Stream<CbomCertificateRow> stream = certificateRepository.streamCbomRowsByOrganizationId(ORG)) {
            rows = stream.toList();
        }

        assertThat(rows)
                .extracting(CbomCertificateRow::getCertificateXref, CbomCertificateRow::getDomain,
                        CbomCertificateRow::getCaProvider, CbomCertificateRow::getIssuer,
                        CbomCertificateRow::getSerialNumber, CbomCertificateRow::getFingerprintSha256,
                        CbomCertificateRow::getSignatureAlgorithm, CbomCertificateRow::getKeySize,
                        CbomCertificateRow::getCommonName, CbomCertificateRow::getSubjectDn,
                        CbomCertificateRow::getSignatureAlgorithmOid, CbomCertificateRow::getKeyUsage,
                        CbomCertificateRow::getExtendedKeyUsage, CbomCertificateRow::getSubjectKeyIdentifier,
                        CbomCertificateRow::getAuthorityKeyIdentifier)
                .containsExactly(
                        tuple("first", "b.example.com", CaProvider.LETS_ENCRYPT, "CN=Issuer", "01AB", "AA:BB",
                                "SHA256withRSA", 2048, "first.example.com", "CN=first.example.com",
                                "1.2.840.113549.1.1.11", "digitalSignature", "serverAuth", "SKI", "AKI"),
                        tuple("third", "a.example.com", CaProvider.LETS_ENCRYPT, "CN=Issuer", "01AB", "AA:BB",
                                "SHA256withRSA", 2048, null, null, null, null, null, null, null));
        assertThat(rows.get(0).getValidFrom()).isEqualTo(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        assertThat(rows.get(0).getValidTo()).isEqualTo(OffsetDateTime.parse("2027-01-01T00:00:00Z"));
    }

    private void saveCert(long id, String xref, long userDomainCertId, String pubKeyAlg, OffsetDateTime deletedAt) {
        saveCert(id, xref, userDomainCertId, pubKeyAlg, deletedAt, "ACTIVE", "2026-01-01 00:00:00Z");
    }

    private void saveCert(long id, String xref, long userDomainCertId, String pubKeyAlg, OffsetDateTime deletedAt,
                          String status, String createdAt) {
        jdbcTemplate.update("""
                insert into certificates (id, certificate_xref, user_domain_cert_id, ca_provider, issuer, serial_number,
                    fingerprint_sha256, valid_from, valid_to, signature_algorithm, public_key_algorithm, key_size,
                    status, created_at, deleted_at)
                values (?, ?, ?, 'LETS_ENCRYPT', 'CN=Issuer', '01AB', 'AA:BB',
                    timestamp with time zone '2026-01-01 00:00:00Z', timestamp with time zone '2027-01-01 00:00:00Z',
                    'SHA256withRSA', ?, 2048, ?, cast(? as timestamp with time zone), ?)
                """, id, xref, userDomainCertId, pubKeyAlg, status, createdAt, deletedAt);
    }
}
