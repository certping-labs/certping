// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.repository.CertificateRepository.PqcAlgorithmCount;
import com.certmanagement.repository.CertificateRepository.PqcCertificateRow;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredAlgorithmCount;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.ANY)
class CertificateRepositoryPqcTest {

    private static final long ORG = 1L;
    private static final long OTHER_ORG = 2L;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private DiscoveredCertRepository discoveredCertRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private long certificateIdSeq = 1L;

    @BeforeEach
    void setUpSchema() {
        jdbcTemplate.execute("drop table if exists certificate_crypto_metadata");
        jdbcTemplate.execute("drop table if exists certificates");
        jdbcTemplate.execute("drop table if exists user_domain_certificate");
        jdbcTemplate.execute("drop table if exists discovered_cert");
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
                    status varchar(50) not null,
                    signature_algorithm varchar(100),
                    public_key_algorithm varchar(50),
                    key_size int,
                    created_at timestamp with time zone not null,
                    deleted_at timestamp with time zone
                )
                """);
        jdbcTemplate.execute("""
                create table certificate_crypto_metadata (
                    id bigint primary key,
                    certificate_xref varchar(100) not null unique,
                    common_name varchar(255),
                    public_key_curve varchar(100),
                    key_usage varchar(255)
                )
                """);
        jdbcTemplate.execute("""
                create table discovered_cert (
                    id bigint primary key,
                    organization_id bigint not null,
                    resource_id varchar(500) not null,
                    domain varchar(500),
                    subject_dn varchar(500),
                    signature_algorithm varchar(100),
                    key_algorithm varchar(100),
                    key_usage varchar(255),
                    serial_number varchar(200),
                    managed boolean,
                    inventory_status varchar(20) not null,
                    created_at timestamp with time zone not null
                )
                """);
        for (long udc = 10; udc <= 15; udc++) {
            jdbcTemplate.update("insert into user_domain_certificate (id, organization_id, domain) values (?, ?, ?)",
                    udc, ORG, "d" + udc + ".example.com");
        }
        jdbcTemplate.update("insert into user_domain_certificate (id, organization_id, domain) values (20, ?, 'other.example.com')", OTHER_ORG);
    }

    @Test
    void countPqcAlgorithms_groupsLiveCertsOfTheOrganizationWithTheirCurveAndKeyUsage() {
        saveCert("rsa-1", 10, "SHA256withRSA", "RSA", 2048);
        saveCert("rsa-2", 11, "SHA256withRSA", "RSA", 2048);
        saveCert("ec-1", 12, "SHA384withECDSA", "EC", 384);
        saveCert("legacy", 13, null, null, null);
        saveDeletedCert("gone", 14, "RSA", 2048);
        saveCert("foreign", 20, "SHA256withRSA", "RSA", 2048);
        saveMetadata("rsa-1", "a.example.com", null, "keyEncipherment");
        saveMetadata("rsa-2", "b.example.com", null, "digitalSignature");
        saveMetadata("ec-1", null, "secp384r1", "digitalSignature");

        List<PqcAlgorithmCount> counts = certificateRepository.countPqcAlgorithmsByOrganizationId(ORG);

        assertThat(counts)
                .extracting(PqcAlgorithmCount::getPublicKeyAlgorithm, PqcAlgorithmCount::getKeySize,
                        PqcAlgorithmCount::getCurve, PqcAlgorithmCount::getKeyUsage, PqcAlgorithmCount::getCount)
                .containsExactlyInAnyOrder(
                        tuple("RSA", 2048, null, "keyEncipherment", 1L),
                        tuple("RSA", 2048, null, "digitalSignature", 1L),
                        tuple("EC", 384, "secp384r1", "digitalSignature", 1L),
                        tuple(null, null, null, null, 1L));
    }

    @Test
    void countPqcAlgorithms_countsOnlyTheCurrentCertificateOfEachLineage() {
        saveCert("first", 10, "SHA256withRSA", "RSA", 2048, "RENEW_SUCCESS");
        saveCert("second", 10, "SHA256withRSA", "RSA", 2048, "RENEW_SUCCESS");
        saveCert("current", 10, "SHA384withECDSA", "EC", 256, "ACTIVE");
        saveCert("renewal-draft", 10, null, null, null, "PENDING");
        saveCert("failed-renewal", 10, null, null, null, "RENEWAL_FAILED");
        saveCert("revoked", 11, "SHA256withRSA", "RSA", 2048, "REVOKED");
        saveCert("reissued", 11, "SHA256withRSA", "RSA", 3072, "ACTIVE");
        saveCert("never-issued", 12, null, null, null, "FAILED");

        assertThat(certificateRepository.countPqcAlgorithmsByOrganizationId(ORG))
                .extracting(PqcAlgorithmCount::getPublicKeyAlgorithm, PqcAlgorithmCount::getKeySize,
                        PqcAlgorithmCount::getCount)
                .containsExactlyInAnyOrder(tuple("EC", 256, 1L), tuple("RSA", 3072, 1L));
        assertThat(certificateRepository.findPqcRowsByOrganizationId(ORG, null, PageRequest.of(0, 10))
                .getContent()).extracting(PqcCertificateRow::getCertificateXref)
                .containsExactlyInAnyOrder("current", "reissued");
    }

    @Test
    void findPqcRows_pagesNewestFirstWithJoinedMetadata() {
        saveCert("first", 10, "SHA256withRSA", "RSA", 2048);
        saveCert("second", 11, "SHA384withECDSA", "EC", 384);
        saveCert("third", 12, null, null, null);
        saveDeletedCert("gone", 13, "RSA", 2048);
        saveCert("foreign", 20, "SHA256withRSA", "RSA", 2048);
        saveMetadata("second", "cn.example.com", "secp384r1", "digitalSignature");

        Page<PqcCertificateRow> page = certificateRepository.findPqcRowsByOrganizationId(
                ORG, null, PageRequest.of(0, 2, Sort.by(Sort.Direction.DESC, "createdAt")));

        assertThat(page.getTotalElements()).isEqualTo(3);
        assertThat(page.getContent())
                .extracting(PqcCertificateRow::getCertificateXref, PqcCertificateRow::getCommonName,
                        PqcCertificateRow::getDomain, PqcCertificateRow::getCurve, PqcCertificateRow::getKeyUsage)
                .containsExactly(
                        tuple("third", null, "d12.example.com", null, null),
                        tuple("second", "cn.example.com", "d11.example.com", "secp384r1", "digitalSignature"));
    }

    @Test
    void findPqcRows_withAlgorithmKeys_matchesNullPartsAsEmptyStrings() {
        saveCert("rsa", 10, "SHA256withRSA", "RSA", 2048);
        saveCert("ec", 11, "SHA384withECDSA", "EC", 384);
        saveCert("ec-no-size", 12, "SHA384withECDSA", "EC", null);
        saveCert("legacy", 13, null, null, null);
        saveMetadata("ec", null, "secp384r1", null);
        saveMetadata("ec-no-size", null, "secp384r1", null);

        Page<PqcCertificateRow> page = certificateRepository.findPqcRowsByOrganizationId(
                ORG, List.of("EC|384|secp384r1", "||"), PageRequest.of(0, 10, Sort.by("createdAt")));

        assertThat(page.getTotalElements()).isEqualTo(2);
        assertThat(page.getContent()).extracting(PqcCertificateRow::getCertificateXref)
                .containsExactly("ec", "legacy");
    }

    @Test
    void discoveredPqc_coversPresentUnmanagedCertsOncePerSerial() {
        saveDiscovered(ORG, "k8s/default/hand-made", "EC-256", "AB01", null, "PRESENT");
        saveDiscovered(ORG, "k8s/other/same-cert", "EC-256", "AB01", false, "PRESENT");
        saveDiscovered(ORG, "acm/no-serial", "RSA_2048", null, null, "UNKNOWN");
        saveDiscovered(ORG, "acm/issued-by-certping", "RSA_2048", "CD02", true, "PRESENT");
        saveDiscovered(ORG, "acm/removed", "RSA_2048", "EF03", false, "MISSING");
        saveDiscovered(ORG, "kv/no-key", null, "0104", false, "PRESENT");
        saveDiscovered(OTHER_ORG, "k8s/foreign", "EC-256", "AB01", false, "PRESENT");

        assertThat(discoveredCertRepository.countPqcAlgorithmsByOrganizationId(ORG))
                .extracting(PqcDiscoveredAlgorithmCount::getKeyAlgorithm, PqcDiscoveredAlgorithmCount::getCount)
                .containsExactlyInAnyOrder(tuple("EC-256", 1L), tuple("RSA_2048", 1L), tuple(null, 1L));
        assertThat(discoveredCertRepository.countPqcRowsByOrganizationId(ORG, null)).isEqualTo(3);
        assertThat(discoveredCertRepository.countPqcRowsByOrganizationId(ORG, List.of("EC-256", ""))).isEqualTo(2);
        assertThat(discoveredCertRepository.findPqcRowsByOrganizationId(ORG, List.of("EC-256"),
                        PageRequest.of(0, 10, Sort.by("createdAt"))))
                .extracting(PqcDiscoveredRow::getResourceId)
                .containsExactly("k8s/default/hand-made");
    }

    private void saveCert(String xref, long userDomainCertId, String sigAlg, String pubKeyAlg, Integer keySize) {
        saveCert(xref, userDomainCertId, sigAlg, pubKeyAlg, keySize, "ACTIVE");
    }

    private void saveCert(String xref, long userDomainCertId, String sigAlg, String pubKeyAlg, Integer keySize,
                          String status) {
        long id = certificateIdSeq++;
        jdbcTemplate.update("""
                insert into certificates (id, certificate_xref, user_domain_cert_id, status, signature_algorithm,
                                          public_key_algorithm, key_size, created_at)
                values (?, ?, ?, ?, ?, ?, ?, timestamp with time zone '2026-01-01 00:00:00Z' + ? second)
                """, id, xref, userDomainCertId, status, sigAlg, pubKeyAlg, keySize, id);
    }

    private void saveDeletedCert(String xref, long userDomainCertId, String pubKeyAlg, Integer keySize) {
        long id = certificateIdSeq++;
        jdbcTemplate.update("""
                insert into certificates (id, certificate_xref, user_domain_cert_id, status, public_key_algorithm,
                                          key_size, created_at, deleted_at)
                values (?, ?, ?, 'ACTIVE', ?, ?, timestamp with time zone '2026-01-01 00:00:00Z',
                        timestamp with time zone '2026-02-01 00:00:00Z')
                """, id, xref, userDomainCertId, pubKeyAlg, keySize);
    }

    private void saveMetadata(String xref, String commonName, String curve, String keyUsage) {
        jdbcTemplate.update("""
                insert into certificate_crypto_metadata (id, certificate_xref, common_name, public_key_curve, key_usage)
                values (?, ?, ?, ?, ?)
                """, certificateIdSeq++, xref, commonName, curve, keyUsage);
    }

    private void saveDiscovered(long organizationId, String resourceId, String keyAlgorithm, String serial,
                                Boolean managed, String inventoryStatus) {
        long id = certificateIdSeq++;
        jdbcTemplate.update("""
                insert into discovered_cert (id, organization_id, resource_id, key_algorithm, serial_number, managed,
                                             inventory_status, created_at)
                values (?, ?, ?, ?, ?, ?, ?, timestamp with time zone '2026-01-01 00:00:00Z' + ? second)
                """, id, organizationId, resourceId, keyAlgorithm, serial, managed, inventoryStatus, id);
    }
}
