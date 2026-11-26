// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The rule that an organization keeps an active admin, on real PostgreSQL with every migration: who
 * the admin count sees, and two concurrent demotions that each would leave the other as the last
 * admin.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class LastOrganizationAdminGuardPostgresTest {

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

    @Autowired private UserRepository users;
    @Autowired private OrganizationRepository organizations;
    @Autowired private RoleRepository roles;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private PermissionGrantPolicy policy;
    private long org1;
    private long org2;

    @BeforeEach
    void seed() {
        JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);
        when(jwtTokenProvider.effectivePermissions(any(), any())).thenReturn(Set.of());
        policy = new PermissionGrantPolicy(users, organizations, jwtTokenProvider);
        jdbc.execute("DELETE FROM user_roles");
        jdbc.execute("DELETE FROM user_permissions");
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM roles WHERE organization_id IS NOT NULL");
        jdbc.execute("DELETE FROM organizations");
        org1 = organization("a");
        org2 = organization("b");
    }

    @Test
    void theCountSeesOnlyOtherActiveLiveSystemRoleAdminsOfTheOrganization() {
        int a = user("a@x", org1, true, false, ROLE_ORGANIZATION_ADMIN);
        int b = user("b@x", org1, true, false, ROLE_ORGANIZATION_ADMIN, "VIEWER", "CERT_MANAGER");
        user("inactive@x", org1, false, false, ROLE_ORGANIZATION_ADMIN);
        user("unset@x", org1, null, false, ROLE_ORGANIZATION_ADMIN);
        user("deleted@x", org1, false, true, ROLE_ORGANIZATION_ADMIN);
        user("deleted-active@x", org1, true, true, ROLE_ORGANIZATION_ADMIN);
        user("viewer@x", org1, true, false, "VIEWER");
        int f = user("f@x", org2, true, false, ROLE_ORGANIZATION_ADMIN);
        long lookalike = jdbc.queryForObject("INSERT INTO roles (name, description, organization_id, is_system_role) "
                + "VALUES (?, 'custom', ?, false) RETURNING id", Long.class, ROLE_ORGANIZATION_ADMIN, org1);
        int g = user("g@x", org1, true, false);
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", g, lookalike);

        assertThat(countOtherAdmins(org1, a)).isEqualTo(1);
        assertThat(countOtherAdmins(org1, b)).isEqualTo(1);
        assertThat(countOtherAdmins(org1, -1)).isEqualTo(2);
        assertThat(countOtherAdmins(org2, f)).isZero();
    }

    @Test
    void twoAdminsDisablingEachOtherAtOnce_leaveOneAdmin() throws Exception {
        int a = user("a@x", org1, true, false, ROLE_ORGANIZATION_ADMIN);
        int b = user("b@x", org1, true, false, ROLE_ORGANIZATION_ADMIN);

        BiConsumer<PermissionGrantPolicy.Caller, User> disable = (caller, target) -> {
            policy.assertMayDeactivate(caller, target);
            target.setActive(false);
        };
        List<Throwable> outcomes = race(a, b, disable, b, a, disable);

        assertOneWonAndOneWasRefused(outcomes);
    }

    @Test
    void disablingOneAdminWhileDemotingTheOther_leavesOneAdmin() throws Exception {
        int a = user("a@x", org1, true, false, ROLE_ORGANIZATION_ADMIN);
        int b = user("b@x", org1, true, false, ROLE_ORGANIZATION_ADMIN);
        Role viewer = roles.findByNameAndOrganizationIsNull("VIEWER").orElseThrow();

        List<Throwable> outcomes = race(
                b, a, (caller, target) -> {
                    policy.assertMayDeactivate(caller, target);
                    target.setActive(false);
                },
                a, b, (caller, target) -> {
                    policy.assertMayChange(caller, target, target.getActive(), Set.of(viewer));
                    target.getRoles().clear();
                    target.getRoles().add(viewer);
                });

        assertOneWonAndOneWasRefused(outcomes);
    }

    private void assertOneWonAndOneWasRefused(List<Throwable> outcomes) {
        assertThat(outcomes).filteredOn(t -> t == null).hasSize(1);
        assertThat(outcomes).filteredOn(t -> t instanceof LastOrganizationAdminException).hasSize(1);
        assertThat(countOtherAdmins(org1, -1)).isEqualTo(1);
    }

    /**
     * Two transactions that both load their target first, then change it through the policy
     * together, holding the change open before committing.
     */
    private List<Throwable> race(int caller1, int target1, BiConsumer<PermissionGrantPolicy.Caller, User> change1,
                                 int caller2, int target2, BiConsumer<PermissionGrantPolicy.Caller, User> change2)
            throws Exception {
        CountDownLatch bothLoaded = new CountDownLatch(2);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<Throwable>> futures = List.of(
                    pool.submit(() -> change(caller1, target1, change1, bothLoaded)),
                    pool.submit(() -> change(caller2, target2, change2, bothLoaded)));
            List<Throwable> outcomes = new ArrayList<>();
            for (Future<Throwable> future : futures) {
                outcomes.add(future.get(30, TimeUnit.SECONDS));
            }
            return outcomes;
        } finally {
            pool.shutdownNow();
        }
    }

    private Throwable change(int callerId, int targetId, BiConsumer<PermissionGrantPolicy.Caller, User> change,
                             CountDownLatch bothLoaded) {
        try {
            new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                User target = users.findById(targetId).orElseThrow();
                target.getRoles().size();
                bothLoaded.countDown();
                await(bothLoaded);
                change.accept(new PermissionGrantPolicy.Caller(callerId, org1, false, true, Set.of(), Set.of()), target);
                users.saveAndFlush(target);
                pause();
            });
            return null;
        } catch (Throwable refused) {
            return refused;
        }
    }

    private long countOtherAdmins(long organizationId, int excludedUserId) {
        return new TransactionTemplate(transactionManager).execute(status -> users
                .countActiveWithSystemRoleInOrganizationExcept(organizationId, ROLE_ORGANIZATION_ADMIN, excludedUserId));
    }

    private long organization(String slug) {
        return jdbc.queryForObject("INSERT INTO organizations (name, domain, slug) VALUES (?, ?, ?) RETURNING id",
                Long.class, slug.toUpperCase(), slug + ".test", slug);
    }

    private int user(String email, long organizationId, Boolean active, boolean deleted, String... systemRoles) {
        int id = jdbc.queryForObject(
                "INSERT INTO users (email, organization_id, active, is_deleted) VALUES (?, ?, ?, ?) RETURNING id",
                Integer.class, email, organizationId, active, deleted);
        for (String role : systemRoles) {
            jdbc.update("INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles "
                    + "WHERE name = ? AND organization_id IS NULL AND is_deleted = false", id, role);
        }
        return id;
    }

    private static void await(CountDownLatch latch) {
        try {
            assertThat(latch.await(10, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void pause() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
