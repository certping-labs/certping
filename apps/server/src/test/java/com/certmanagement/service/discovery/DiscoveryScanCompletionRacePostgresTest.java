// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.repository.DiscoveryScanRepository;
import com.certmanagement.service.audit.DiscoveryAuditRecorder;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.OffsetDateTime;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The agent sends the last batch and then the completion signal; the server can handle them at the
 * same time. The batch handler first reads the scan without a lock (the cancelled check), so its
 * managed copy is stale by the time it locks the row. Writing that copy back used to erase the
 * completion and leave the scan, and its scan config, stuck as running.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import(DiscoveryScanService.class)
class DiscoveryScanCompletionRacePostgresTest {

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

    @MockitoBean private DiscoveryReconciliationService reconciliationService;
    @MockitoBean private DiscoveryAuditRecorder discoveryAudit;

    @Autowired private DiscoveryScanService scans;
    @Autowired private DiscoveryScanRepository repository;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void completionCommittedWhileABatchIsInFlightIsNotLost() {
        Long orgId = jdbc.queryForObject("""
                INSERT INTO organizations (name, domain, slug, org_type, is_deleted)
                VALUES ('Org ' || md5(random()::text), md5(random()::text) || '.test',
                        'org-' || md5(random()::text), 'B2B', false)
                RETURNING id
                """, Long.class);
        String requestId = "req-" + UUID.randomUUID();
        repository.save(DiscoveryScanEntity.builder()
                .requestId(requestId)
                .organizationId(orgId)
                .targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-1")
                .scopeKey("a".repeat(64))
                .status(DiscoveryScanStatus.DISPATCHED)
                .receivedBatchIndices(new Integer[0])
                .requestedAt(OffsetDateTime.now())
                .build());

        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        tx.executeWithoutResult(status -> {
            // The batch handler's unlocked read, before the completion commits.
            assertThat(scans.findStatus(requestId)).contains(DiscoveryScanStatus.DISPATCHED);

            // The completion is handled by another thread and commits first.
            CompletableFuture.runAsync(() -> new TransactionTemplate(transactionManager)
                    .executeWithoutResult(other -> scans.recordCompletion(completion(requestId, orgId), orgId)))
                    .join();

            scans.beginBatch(batch(requestId, orgId), orgId);
            scans.completeBatch(batch(requestId, orgId), 1);
        });

        DiscoveryScanEntity saved = repository.findById(requestId).orElseThrow();
        assertThat(saved.isCompletionReceived()).isTrue();
        assertThat(saved.getStatus()).isEqualTo(DiscoveryScanStatus.COMPLETE);
    }

    private static CertDiscoveryResponse batch(String requestId, Long orgId) {
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId(requestId);
        response.setOrganizationId(String.valueOf(orgId));
        response.setTargetType("KUBERNETES_SECRETS");
        response.setBatchIndex(0);
        response.setTotalBatches(1);
        return response;
    }

    private static DiscoveryCompleteMessage completion(String requestId, Long orgId) {
        DiscoveryCompleteMessage message = new DiscoveryCompleteMessage();
        message.setRequestId(requestId);
        message.setOrganizationId(String.valueOf(orgId));
        message.setTargetType("KUBERNETES_SECRETS");
        message.setTotalCerts(1);
        message.setCompletedAt("2026-10-27T07:26:30Z");
        return message;
    }
}
