// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;
import com.certmanagement.dto.audit.AuditPlatformFilterRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A super admin's actions never show the customer the person, their email or address. Staffness is the action's:
 * rows take it from their context ({@link AuditEvents}), and the read side trusts what is stored. A member of
 * another organization, or of none, is never staff by that alone.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditEventQueryStore.class, AuditTrailReader.class, AuditVisibilityPolicy.class,
        AuditStaffMaskingPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditStaffMaskingPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    @TestConfiguration
    static class Beans {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

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

    @MockitoBean private FeatureFlagService featureFlags;
    @Autowired private AuditEventStore store;
    @Autowired private AuditEventQueryStore queries;
    @Autowired private AuditTrailReader reader;
    @Autowired private AuditVisibilityPolicy policy;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long acme;
    private long globex;
    private int alice;
    private int superAdmin;
    private int superAdminInAcme;

    @BeforeEach
    void seed() {
        when(featureFlags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        YearMonth month = YearMonth.now(ZoneOffset.UTC);
        store.createPartition(month.minusMonths(1));
        store.createPartition(month);
        jdbc.execute("DELETE FROM user_roles");
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        acme = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id", Long.class);
        globex = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug) "
                + "VALUES ('Globex', 'globex.test', 'globex') RETURNING id", Long.class);
        alice = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, acme);
        superAdmin = superAdmin("super_admin@certping.example", null);
        // A super admin who is also a member of the organization: still CertPing staff in its trail.
        superAdminInAcme = superAdmin("ops@certping.example", acme);
        GatewayRequestContext.set(alice, String.valueOf(acme), "req-test", null);
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void aSuperAdminsRowsAreStaffWhetherOrNotTheyAreAMember() throws IOException {
        // The context knows the actor was a super admin when they acted, in any trail.
        for (int admin : new int[]{superAdminInAcme, superAdmin}) {
            try (AuditScope scope = AuditScope.user(admin, acme, "PASSWORD", true)) {
                store.insert(AuditEvents.success(AuditEventType.FEATURE_PAUSED,
                        AuditSubject.builder().name("Discovery").count(3).build()));
            }
        }

        assertThat(jdbc.queryForList("SELECT actor_staff FROM audit_events", Boolean.class)).containsOnly(true);
        assertMaskedForTheCustomer(2);

        AuditTrailExporter exporter = new AuditTrailExporter(reader, queries, store, mock(AuditedReads.class),
                JsonMapper.builderWithJackson2Defaults()
                        .findAndAddModules()
                        .build(), Clock.systemUTC(), transactionManager, 10_000, 10, 4);
        ByteArrayOutputStream csv = new ByteArrayOutputStream();
        exporter.exportActivity(new AuditEventFilterRequest(), "csv", false, policy.viewer(false, acme))
                .body().writeTo(csv);
        assertThat(csv.toString(StandardCharsets.UTF_8)).contains("Platform administrator").doesNotContain("Super Admin")
                .doesNotContain("super_admin@certping.example").doesNotContain("10.20.0.5");
    }

    @Test
    void aMemberOfAnotherOrganizationOrOfNoneIsNeverStaffAndReadsAsThemselvesOrAFormerMember() {
        int mover = member("bob@acme.test", "Bob Mover", acme);
        int platformAccount = member("partner@example.test", "Pat Partner", null);
        // A user gone before the row was written has no label left; Bob acted while a member of Acme, then moved.
        for (int actor : new int[]{999_999, platformAccount, mover}) {
            try (AuditScope scope = AuditScope.user(actor, acme, "PASSWORD", false)) {
                store.insert(AuditEvents.success(AuditEventType.ORGANIZATION_UPDATED, AuditSubject.NONE));
            }
        }
        jdbc.update("UPDATE users SET organization_id = ? WHERE id = ?", globex, mover);

        assertThat(jdbc.queryForList("SELECT actor_staff FROM audit_events", Boolean.class)).containsOnly(false);
        List<AuditEventEntryDto> customer = reader.read(new AuditEventFilterRequest(), null, 20, false,
                policy.viewer(false, acme)).content();
        assertThat(customer).extracting(AuditEventEntryDto::actorName)
                .containsExactly("Bob Mover", "Pat Partner", AuditDisplayNames.FORMER_ACTOR)
                .doesNotContain(AuditDisplayNames.STAFF);
        assertThat(reader.readPlatform(new AuditPlatformFilterRequest(), 20, policy.viewer(true, acme)).content())
                .extracting(AuditPlatformEntryDto::staff).containsOnly(false);
    }

    @Test
    void aRequesterIsCertPingSupportOnlyWhenASuperAdminAndOtherwiseNamedOrAFormerMember() {
        int moved = member("dave@acme.test", "Dave", globex);
        int gone = member("erin@acme.test", "Erin", globex);
        jdbc.update("UPDATE users SET is_deleted = true WHERE id = ?", gone);
        for (int requester : new int[]{superAdmin, moved, gone}) {
            try (AuditScope scope = AuditScope.system("trigger-renewals", acme)) {
                store.insert(AuditEvents.success(AuditEventType.FEATURE_RESUMED, AuditSubject.builder()
                        .name("Discovery").count(1).attributes(Map.of("requestedBy", String.valueOf(requester)))
                        .build()));
            }
        }

        assertThat(reader.read(new AuditEventFilterRequest(), null, 20, false, policy.viewer(false, acme)).content())
                .extracting(AuditEventEntryDto::requestedByName)
                .containsExactly(AuditDisplayNames.FORMER_MEMBER, "Dave", AuditDisplayNames.STAFF);
    }

    @Test
    void underTheStaffSettingTheTriggerLetsOnlyActorStaffTurnOn() {
        int member = member("frank@acme.test", "Frank", acme);
        jdbc.update("INSERT INTO audit_events (occurred_at, visibility, event, category, organization_id, "
                + "actor_type, actor_user_id, actor_label, actor_staff, action, resource_type, outcome, summary, "
                + "ip_address) VALUES (now() - interval '1 minute', 'CUSTOMER', 'organization.deleted', "
                + "'ORGANIZATION', ?, 'USER', ?, 'Someone', false, 'DELETE', 'ORGANIZATION', 'SUCCESS', "
                + "'Deleted the organization', '10.20.0.5')", acme, member);

        // With the setting on, only false -> true of actor_staff passes; every other change is refused.
        assertThat(underStaffFix("UPDATE audit_events SET actor_staff = true WHERE actor_user_id = " + member))
                .isNull();
        assertThat(underStaffFix("UPDATE audit_events SET actor_staff = false WHERE actor_user_id = " + member))
                .contains("append-only");
        jdbc.update("INSERT INTO audit_events (occurred_at, visibility, event, category, organization_id, actor_type, "
                + "actor_user_id, actor_staff, action, resource_type, outcome, summary) VALUES (now(), 'CUSTOMER', "
                + "'organization.updated', 'ORGANIZATION', ?, 'USER', ?, false, 'UPDATE', 'ORGANIZATION', 'SUCCESS', "
                + "'Changed the settings')", acme, alice);
        assertThat(underStaffFix("UPDATE audit_events SET actor_staff = true, summary = 'x' WHERE actor_user_id = "
                + alice)).contains("append-only");
        assertThat(underStaffFix("DELETE FROM audit_events WHERE actor_user_id = " + alice)).contains("append-only");
        assertThat(failure(() -> jdbc.update("UPDATE audit_events SET actor_staff = true WHERE actor_user_id = ?",
                alice))).as("without the setting").contains("append-only");
        // The GDPR erasure exception still works.
        assertThat(store.pseudonymiseActor(alice)).isEqualTo(1);
    }

    @Test
    void aFormerSuperAdminWhoseAssignmentIsSoftDeletedIsNotStaffAnywhere() throws IOException {
        int former = superAdmin("former@certping.example", null);
        jdbc.update("UPDATE user_roles SET is_deleted = true WHERE user_id = ?", former);

        assertFormerSuperAdminIsNotStaff(former);
    }

    @Test
    void aSuperAdminWhoseSystemRoleIsSoftDeletedIsNotStaffAnywhere() throws IOException {
        int former = superAdmin("former-role@certping.example", null);
        jdbc.update("UPDATE roles SET is_deleted = true WHERE name = 'SUPER_ADMIN' AND organization_id IS NULL");
        try {
            assertFormerSuperAdminIsNotStaff(former);
        } finally {
            jdbc.update("UPDATE roles SET is_deleted = false WHERE name = 'SUPER_ADMIN' AND organization_id IS NULL");
        }
    }

    /** Not a platform administrator as an actor, nor as a requester. */
    private void assertFormerSuperAdminIsNotStaff(int former) throws IOException {
        jdbc.update("INSERT INTO audit_events (occurred_at, visibility, event, category, organization_id, "
                + "actor_type, actor_user_id, actor_label, actor_staff, action, resource_type, outcome, summary) "
                + "VALUES (now() - interval '1 minute', 'CUSTOMER', 'organization.deleted', 'ORGANIZATION', ?, 'USER', "
                + "?, 'Former Admin', false, 'DELETE', 'ORGANIZATION', 'SUCCESS', 'Deleted the organization')",
                acme, former);
        try (AuditScope scope = AuditScope.system("trigger-renewals", acme)) {
            store.insert(AuditEvents.success(AuditEventType.FEATURE_RESUMED, AuditSubject.builder()
                    .name("Discovery").count(1).attributes(Map.of("requestedBy", String.valueOf(former))).build()));
        }

        assertThat(jdbc.queryForList("SELECT actor_staff FROM audit_events WHERE actor_user_id = ?", Boolean.class,
                former)).containsExactly(false);
        List<AuditEventEntryDto> customer = reader.read(new AuditEventFilterRequest(), null, 20, false,
                policy.viewer(false, acme)).content();
        assertThat(customer).extracting(AuditEventEntryDto::actorName).doesNotContain(AuditDisplayNames.STAFF);
        assertThat(customer.get(0).requestedByName()).isEqualTo("Super Admin");
    }

    /** Runs {@code sql} with certping.audit_staff_fix on; the failure's message, or null when it passed. */
    private String underStaffFix(String sql) {
        return failure(() -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.queryForObject("SELECT set_config('certping.audit_staff_fix', 'on', true)", String.class);
            jdbc.update(sql);
        }));
    }

    private static String failure(Runnable work) {
        try {
            work.run();
            return null;
        } catch (RuntimeException e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            return String.valueOf(root.getMessage());
        }
    }

    private void assertMaskedForTheCustomer(int rows) {
        List<AuditEventEntryDto> customer = reader.read(new AuditEventFilterRequest(), null, 20, false,
                policy.viewer(false, acme)).content();
        assertThat(customer).hasSize(rows).allSatisfy(entry -> {
            assertThat(entry.actorName()).isEqualTo("Platform administrator");
            assertThat(entry.userId()).isNull();
            assertThat(entry.userEmail()).isNull();
            assertThat(entry.ipAddress()).isNull();
            assertThat(entry.userAgent()).isNull();
        });

        List<AuditPlatformEntryDto> platform = reader.readPlatform(new AuditPlatformFilterRequest(), 20,
                policy.viewer(true, acme)).content();
        assertThat(platform).hasSize(rows).allSatisfy(entry -> {
            assertThat(entry.staff()).isTrue();
            assertThat(entry.entry().userId()).as("the platform sees the person").isIn(superAdmin, superAdminInAcme);
        });
    }

    private int superAdmin(String email, Long organizationId) {
        int id = member(email, "Super Admin", organizationId);
        grantSuperAdmin(id);
        return id;
    }

    private int member(String email, String name, Long organizationId) {
        return jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) VALUES (?, ?, ?) "
                + "RETURNING id", Integer.class, email, name, organizationId);
    }

    private void grantSuperAdmin(int userId) {
        jdbc.update("INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles "
                + "WHERE name = 'SUPER_ADMIN' AND organization_id IS NULL", userId);
    }
}
