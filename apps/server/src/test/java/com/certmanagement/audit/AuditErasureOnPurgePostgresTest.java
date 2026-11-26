// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.service.GlobalSettingsService;
import com.certmanagement.service.SoftDeletePurgeService;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

/**
 * GDPR erasure at the user purge: the members {@link SoftDeletePurgeService} hard-deletes lose their names
 * from the audit rows they acted in, in the purge's transaction, and keep them if the purge rolls back.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({SoftDeletePurgeService.class, AuditErasure.class, AuditEventStore.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditErasureOnPurgePostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

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

    @MockitoBean private GlobalSettingsService globalSettingsService;
    @MockitoBean private com.certmanagement.service.audit.OrganizationAuditRecorder organizationAudit;
    @MockitoBean private SchedulerExecutionPolicy executionPolicy;
    @MockitoSpyBean private com.certmanagement.repository.UserRepository userRepository;
    @Autowired private SoftDeletePurgeService purgeService;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long organizationId;
    private int purgedId;
    private int keptId;

    @BeforeEach
    void seed() {
        reset(userRepository);
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        store.createPartition(YearMonth.now(ZoneOffset.UTC));
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        purgedId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id, is_deleted, updated_at) "
                + "VALUES ('gone@acme.test', 'Gone Member', ?, true, now() - interval '90 days') RETURNING id",
                Integer.class, organizationId);
        keptId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('kept@acme.test', 'Kept Member', ?) RETURNING id", Integer.class, organizationId);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> store.insertAll(List.of(
                row(purgedId), row(keptId))));
    }

    private AuditEventRow row(int actorUserId) {
        return AuditEventRow.builder().occurredAt(Instant.now()).visibility(AuditVisibility.CUSTOMER)
                .event("member.deleted").category("ACCESS_CONTROL").organizationId(organizationId)
                .actorType(AuditActorType.USER).actorUserId(actorUserId).action("USER_DELETED").resourceType("USER")
                .outcome(AuditOutcome.SUCCESS).summary("Removed a member").build();
    }

    private List<String> labels() {
        return jdbc.queryForList("SELECT actor_label FROM audit_events ORDER BY actor_user_id", String.class);
    }

    @Test
    void thePurgedMemberIsPseudonymisedAndTheOthersAreNot() {
        assertThat(labels()).containsExactly("Gone Member", "Kept Member");

        SoftDeletePurgeService.PurgeResult result = new TransactionTemplate(transactionManager)
                .execute(status -> purgeService.purgeOrganization(organizationId, 30));

        assertThat(result.usersDeleted()).isOne();
        assertThat(jdbc.queryForList("SELECT actor_user_id || ':' || actor_label FROM audit_events "
                + "ORDER BY actor_user_id", String.class))
                .containsExactly(purgedId + ":" + AuditEventStore.ERASED_ACTOR_LABEL, keptId + ":Kept Member");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class))
                .as("the rows themselves are kept").isEqualTo(2);
    }

    @Test
    void aPurgeThatRollsBackLeavesTheNameAsItWas() {
        doThrow(new IllegalStateException("purge failed"))
                .when(userRepository).hardDeleteByOrganizationIdAndUpdatedAtBefore(anyLong(), any());

        assertThatThrownBy(() -> new TransactionTemplate(transactionManager)
                .execute(status -> purgeService.purgeOrganization(organizationId, 30)))
                .isInstanceOf(IllegalStateException.class);

        assertThat(labels()).containsExactly("Gone Member", "Kept Member");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM users WHERE id = ?", Integer.class, purgedId)).isOne();
    }
}
