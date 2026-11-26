// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DeploymentEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.ANY)
class DeploymentRepositoryTest {

    @Autowired
    private DeploymentRepository deploymentRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private static final Long ORGANIZATION_ID = 1L;
    private static final Long OTHER_ORGANIZATION_ID = 2L;
    private long deploymentIdSeq = 1000L;

    @BeforeEach
    void setUpSchema() {
        jdbcTemplate.execute("drop table if exists deployments");
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
                create table deployments (
                    id bigint primary key,
                    request_id varchar(100) not null unique,
                    correlation_id varchar(100),
                    organization_id bigint not null,
                    certificate_xref varchar(100) not null,
                    user_domain_cert_id bigint,
                    deployment_credential_xref varchar(100),
                    target_type varchar(50) not null,
                    flow_type varchar(50) not null,
                    status varchar(50) not null,
                    cert_secret_handle varchar(500),
                    deployment_cred_handle varchar(500),
                    target_resource_id varchar(1000),
                    error_code varchar(100),
                    error_detail varchar(4000),
                        requested_at TIMESTAMP WITH TIME ZONE not null,
                        published_at TIMESTAMP WITH TIME ZONE,
                        responded_at TIMESTAMP WITH TIME ZONE,
                        completed_at TIMESTAMP WITH TIME ZONE,
                    source varchar(100),
                    metadata varchar(4000),
                        is_deleted boolean not null default false,
                        created_at TIMESTAMP WITH TIME ZONE not null,
                        updated_at TIMESTAMP WITH TIME ZONE not null
                )
                """);
    }

    @Test
    void search_withAllOptionalFiltersNull_returnsOrganizationDeployments() {
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A");
        saveDeployment(OTHER_ORGANIZATION_ID, "cert-b", "FAILED", "TARGET_B", "FLOW_B");

        var page = deploymentRepository.search(
                ORGANIZATION_ID,
                null,
                null,
                null,
                null,
                false,
                null,
                null,
                null,
                org.springframework.data.domain.PageRequest.of(0, 10));

        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getContent()).extracting(DeploymentEntity::getCertificateXref).containsExactly("cert-a");
    }

    @Test
    void search_withSomeFiltersNull_stillAppliesProvidedFilters() {
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A");
        saveDeployment(ORGANIZATION_ID, "cert-a", "FAILED", "TARGET_A", "FLOW_A");
        saveDeployment(ORGANIZATION_ID, "cert-b", "SUCCESS", "TARGET_B", "FLOW_B");

        var page = deploymentRepository.search(
                ORGANIZATION_ID,
                "cert-a",
                null,
                "TARGET_A",
                null,
                false,
                null,
                null,
                null,
                org.springframework.data.domain.PageRequest.of(0, 10));

        assertThat(page.getTotalElements()).isEqualTo(2);
        assertThat(page.getContent()).extracting(DeploymentEntity::getStatus).containsExactlyInAnyOrder("SUCCESS", "FAILED");
    }

    @Test
    void summary_withNullOptionalFilters_returnsCountsWithoutError() {
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A");
        saveDeployment(ORGANIZATION_ID, "cert-b", "FAILED", "TARGET_A", "FLOW_A");
        saveDeployment(ORGANIZATION_ID, "cert-c", "PUBLISH_FAILED", "TARGET_A", "FLOW_A");
        saveDeployment(ORGANIZATION_ID, "cert-d", "DEPLOYING", "TARGET_A", "FLOW_A");
        saveDeployment(OTHER_ORGANIZATION_ID, "cert-e", "SUCCESS", "TARGET_A", "FLOW_A");

        Object[] summary = deploymentRepository.summary(
                ORGANIZATION_ID,
                null,
                null,
                null,
                null,
                false,
                null,
                null,
                null);

        assertThat(summary).hasSize(1);
        assertThat((Object[]) summary[0]).containsExactly(
            4L,
            1L,
            1L,
            1L,
            1L);
    }

            @Test
            void search_withUserDomainCertIdFilter_returnsOnlyMatchingDeployments() {
            Long udcA = 10L;
            Long udcB = 11L;

            saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A", udcA);
            saveDeployment(ORGANIZATION_ID, "cert-b", "SUCCESS", "TARGET_A", "FLOW_A", udcB);

            var page = deploymentRepository.search(
                ORGANIZATION_ID,
                null,
                null,
                null,
                null,
                true,
                udcA,
                null,
                null,
                org.springframework.data.domain.PageRequest.of(0, 10));

            assertThat(page.getTotalElements()).isEqualTo(1);
            assertThat(page.getContent()).extracting(DeploymentEntity::getCertificateXref).containsExactly("cert-a");
            }

            @Test
            void summary_withUserDomainCertIdFilter_countsOnlyMatchingDeployments() {
            Long udcA = 10L;
            Long udcB = 11L;

            saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A", udcA);
            saveDeployment(ORGANIZATION_ID, "cert-b", "FAILED", "TARGET_A", "FLOW_A", udcB);

            Object[] summary = deploymentRepository.summary(
                ORGANIZATION_ID,
                null,
                null,
                null,
                null,
                true,
                udcA,
                null,
                null);

            assertThat(summary).hasSize(1);
            assertThat((Object[]) summary[0]).containsExactly(
                1L,
                1L,
                0L,
                0L,
                0L);
            }

        @Test
        void search_withFromAndTo_filtersByCreatedAtRange() {
        saveDeployment(
            ORGANIZATION_ID,
            "cert-old",
            "SUCCESS",
            "TARGET_A",
            "FLOW_A",
            OffsetDateTime.parse("2026-04-01T00:00:00Z"));
        saveDeployment(
            ORGANIZATION_ID,
            "cert-in-range",
            "SUCCESS",
            "TARGET_A",
            "FLOW_A",
            OffsetDateTime.parse("2026-04-08T12:00:00Z"));
        saveDeployment(
            ORGANIZATION_ID,
            "cert-new",
            "SUCCESS",
            "TARGET_A",
            "FLOW_A",
            OffsetDateTime.parse("2026-04-12T00:00:00Z"));

        var page = deploymentRepository.search(
            ORGANIZATION_ID,
            null,
            null,
            null,
            null,
            false,
            null,
            OffsetDateTime.parse("2026-04-08T00:00:00Z"),
            OffsetDateTime.parse("2026-04-10T00:00:00Z"),
            org.springframework.data.domain.PageRequest.of(0, 10));

        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getContent()).extracting(DeploymentEntity::getCertificateXref).containsExactly("cert-in-range");
        }

        @Test
        void summary_withProvidedFilters_returnsOnlyMatchingRows() {
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "AWS_ACM", "MANUAL");
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "AWS_ACM", "AUTO_POST_ISSUANCE");
        saveDeployment(ORGANIZATION_ID, "cert-a", "FAILED", "AWS_ACM", "MANUAL");
        saveDeployment(ORGANIZATION_ID, "cert-b", "SUCCESS", "AZURE_KV", "MANUAL");

        Object[] summary = deploymentRepository.summary(
            ORGANIZATION_ID,
            "cert-a",
            "SUCCESS",
            "AWS_ACM",
            "MANUAL",
            false,
            null,
            null,
            null);

        assertThat(summary).hasSize(1);
        assertThat((Object[]) summary[0]).containsExactly(
            1L,
            1L,
            0L,
            0L,
            0L);
        }

    @Test
    void summarizeByUserDomainCert_withNoFilters_returnsAllUdcsWithCounts() {
        Long udcA = 10L;
        Long udcB = 11L;

        saveUserDomainCert(udcA, ORGANIZATION_ID, "alpha.example.com");
        saveUserDomainCert(udcB, ORGANIZATION_ID, "beta.example.com");
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS",      "TARGET_A", "FLOW_A", udcA);
        saveDeployment(ORGANIZATION_ID, "cert-a", "FAILED",       "TARGET_A", "FLOW_A", udcA);
        saveDeployment(ORGANIZATION_ID, "cert-b", "PUBLISH_FAILED","TARGET_A", "FLOW_A", udcB);

        var page = deploymentRepository.summarizeByUserDomainCert(
                ORGANIZATION_ID, null, false, null, false,
                org.springframework.data.domain.PageRequest.of(0, 10,
                        org.springframework.data.domain.Sort.by("domain")));

        assertThat(page.getTotalElements()).isEqualTo(2);
        Object[] rowA = page.getContent().stream()
                .filter(r -> udcA.equals(r[0])).findFirst().orElseThrow();
        assertThat(((Number) rowA[2]).longValue()).isEqualTo(2L); // total
        assertThat(((Number) rowA[3]).longValue()).isEqualTo(1L); // success
        assertThat(((Number) rowA[4]).longValue()).isEqualTo(1L); // failed+publishFailed

        Object[] rowB = page.getContent().stream()
                .filter(r -> udcB.equals(r[0])).findFirst().orElseThrow();
        assertThat(((Number) rowB[2]).longValue()).isEqualTo(1L);
        assertThat(((Number) rowB[3]).longValue()).isEqualTo(0L);
        assertThat(((Number) rowB[4]).longValue()).isEqualTo(1L);
    }

    @Test
    void summarizeByUserDomainCert_withDomainFilter_returnsOnlyMatchingUdcs() {
        Long udcA = 10L;
        Long udcB = 11L;

        saveUserDomainCert(udcA, ORGANIZATION_ID, "alpha.example.com");
        saveUserDomainCert(udcB, ORGANIZATION_ID, "beta.other.io");
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A", udcA);
        saveDeployment(ORGANIZATION_ID, "cert-b", "FAILED",  "TARGET_A", "FLOW_A", udcB);

        var page = deploymentRepository.summarizeByUserDomainCert(
                ORGANIZATION_ID, "example", false, null, false,
                org.springframework.data.domain.PageRequest.of(0, 10,
                        org.springframework.data.domain.Sort.by("domain")));

        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getContent().get(0)[0]).isEqualTo(udcA);
        assertThat(page.getContent().get(0)[1]).isEqualTo("alpha.example.com");
    }

    @Test
    void summarizeByUserDomainCert_withUdcFilter_returnsSingleUdc() {
        Long udcA = 10L;
        Long udcB = 11L;

        saveUserDomainCert(udcA, ORGANIZATION_ID, "alpha.example.com");
        saveUserDomainCert(udcB, ORGANIZATION_ID, "beta.example.com");
        saveDeployment(ORGANIZATION_ID, "cert-a", "SUCCESS", "TARGET_A", "FLOW_A", udcA);
        saveDeployment(ORGANIZATION_ID, "cert-b", "SUCCESS", "TARGET_A", "FLOW_A", udcB);

        var page = deploymentRepository.summarizeByUserDomainCert(
                ORGANIZATION_ID, null, true, udcA, false,
                org.springframework.data.domain.PageRequest.of(0, 10,
                        org.springframework.data.domain.Sort.by("domain")));

        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getContent().get(0)[0]).isEqualTo(udcA);
        assertThat(((Number) page.getContent().get(0)[2]).longValue()).isEqualTo(1L);
    }

    @Test
    void summarizeByUserDomainCert_udcWithNoDeployments_returnZeroCounts() {
        Long udcA = 401L;
        saveUserDomainCert(udcA, ORGANIZATION_ID, "alpha.example.com");
        // no deployments saved for udcA

        var page = deploymentRepository.summarizeByUserDomainCert(
                ORGANIZATION_ID, null, false, null, false,
                org.springframework.data.domain.PageRequest.of(0, 10,
                        org.springframework.data.domain.Sort.by("domain")));

        assertThat(page.getTotalElements()).isEqualTo(1);
        Object[] row = page.getContent().get(0);
        assertThat(((Number) row[2]).longValue()).isEqualTo(0L);
        assertThat(((Number) row[3]).longValue()).isEqualTo(0L);
        assertThat(((Number) row[4]).longValue()).isEqualTo(0L);
    }

    private void saveUserDomainCert(Long id, Long organizationId, String domain) {
        jdbcTemplate.update("""
                insert into user_domain_certificate (id, organization_id, domain)
                values (?, ?, ?)
                """,
                id, organizationId, domain);
    }

    private void saveDeployment(Long organizationId, String certificateXref, String status, String targetType, String flowType) {
        saveDeployment(organizationId, certificateXref, status, targetType, flowType, null,
                OffsetDateTime.parse("2026-04-08T00:00:00Z"));
    }

    private void saveDeployment(Long organizationId, String certificateXref, String status, String targetType, String flowType,
                                Long userDomainCertId) {
        saveDeployment(organizationId, certificateXref, status, targetType, flowType, userDomainCertId,
                OffsetDateTime.parse("2026-04-08T00:00:00Z"));
    }

    private void saveDeployment(Long organizationId, String certificateXref, String status, String targetType, String flowType,
                                OffsetDateTime createdAt) {
        saveDeployment(organizationId, certificateXref, status, targetType, flowType, null, createdAt);
    }

    private void saveDeployment(Long organizationId, String certificateXref, String status, String targetType, String flowType,
                                Long userDomainCertId, OffsetDateTime createdAt) {
        long deploymentId = nextDeploymentId();
        jdbcTemplate.update("""
                insert into deployments (
                    id, request_id, correlation_id, organization_id, certificate_xref, user_domain_cert_id,
                    deployment_credential_xref, target_type, flow_type, status,
                    cert_secret_handle, deployment_cred_handle, target_resource_id,
                    error_code, error_detail, requested_at, published_at,
                    responded_at, completed_at, source, metadata, created_at, updated_at
                ) values (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                deploymentId,
                "req-" + deploymentId,
                null,
                organizationId,
                certificateXref,
                userDomainCertId,
                null,
                targetType,
                flowType,
                status,
                null,
                null,
                null,
                null,
                null,
                createdAt,
                null,
                null,
                null,
                null,
                null,
                createdAt,
                createdAt);
    }

    private long nextDeploymentId() {
        return deploymentIdSeq++;
    }
}