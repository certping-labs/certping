// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.audit.AuthAuditRecorder;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * Account lockout on real PostgreSQL 15 (the audit tests' version) with the real sign-in audit: the
 * failed-attempt count survives the refusal, a lock refuses the right password, runs out, and is
 * cleared by a sign-in; parallel attempts lose no count and never need two pool connections at once.
 * Covers both password endpoints: {@code /api/auth/login} ({@link UnifiedAuthService}) and
 * {@code /api/v1/admin/login} ({@link AdminUserService#authenticate}). The limit is the default; the lock
 * lasts {@value #LOCK_SECONDS}s, long enough that it cannot run out during a slow parallel burst, and the
 * tests that need it expired move it into the past.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "spring.flyway.enabled=false",
        "app.auth.lockout.duration=PT" + AccountLockoutPostgresTest.LOCK_SECONDS + "S",
        // Fewer connections than parallel sign-ins: a sign-in that needed two at once would starve the
        // pool and fail after this timeout instead of being counted.
        "spring.datasource.hikari.maximum-pool-size=" + AccountLockoutPostgresTest.POOL,
        "spring.datasource.hikari.connection-timeout=3000",
        "certping.audit.async.flush-interval=50ms",
        "certping.audit.async.retry-for=1s",
        "app.bootstrap-super-admin.username=unused",
        "app.bootstrap-super-admin.email=unused@certping.test",
        "app.bootstrap-super-admin.password=unused",
        "app.bootstrap-super-admin.display-name=unused"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AdminUserService.class, PasswordPolicy.class, UnifiedAuthService.class, LoginAttemptService.class, AuditAsyncWriter.class, AuditEventStore.class, AuditRecorder.class,
        AuthAuditRecorder.class, com.certmanagement.service.audit.AccessAuditRecorder.class,
        JacksonAutoConfiguration.class, AccountLockoutPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccountLockoutPostgresTest {

    static final int LOCK_SECONDS = 60;
    static final int POOL = 4;
    static final int PARALLEL = 12;
    private static final int MAX = User.MAX_FAILED_ATTEMPTS;

    private static final String USERNAME = "lock_admin";
    private static final String EMAIL = "lock_admin@certping.test";
    private static final String CUSTOMER_EMAIL = "carol@acme.test";
    private static final String PASSWORD = "Correct-Horse-4821";
    private static final String WRONG = "wrong-password";
    private static final String INVALID = "Invalid username or password";
    private static final String LOCKED = "Account is locked. Try again later.";

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:15-alpine");

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

    /**
     * A real encoder, at the cheapest cost, so the password check is the real one; and a clock the test
     * can move past the sign-in audit's one-row-a-minute throttle.
     */
    @TestConfiguration(proxyBeanMethods = false)
    static class Beans {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(4);
        }

        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        AuditClock clock() {
            return new AuditClock();
        }
    }

    /** System time plus an offset the test advances. */
    static final class AuditClock extends Clock {
        private final AtomicLong offsetMillis = new AtomicLong();

        void advance(Duration by) {
            offsetMillis.addAndGet(by.toMillis());
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis());
        }

        @Override
        public long millis() {
            return System.currentTimeMillis() + offsetMillis.get();
        }
    }

    @MockitoBean private JwtTokenProvider jwtTokenProvider;
    @MockitoBean private RefreshTokenService refreshTokenService;
    @MockitoBean private PermissionGrantPolicy grantPolicy;

    @Autowired private AdminUserService adminUserService;
    @Autowired private UnifiedAuthService unifiedAuthService;
    @Autowired private LoginAttemptService loginAttemptService;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private AuditEventStore store;
    @Autowired private AuditClock auditClock;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private final SimpleMeterRegistry lockouts = new SimpleMeterRegistry();
    private int userId;
    private int customerId;
    private long organizationId;
    /** Audit rows are written in the background: one queued in the test before can land after the cleanup. */
    private OffsetDateTime testStart;

    @BeforeEach
    void seed() {
        clean();
        testStart = OffsetDateTime.now(ZoneOffset.UTC);
        YearMonth month = YearMonth.now(ZoneOffset.UTC);
        store.createPartition(month);
        store.createPartition(month.plusMonths(1));
        String hash = passwordEncoder.encode(PASSWORD);
        // No organization: the shape of a SUPER_ADMIN account, which is staff.
        userId = jdbc.queryForObject("INSERT INTO users (email, username, password_hash, auth_method, active) "
                + "VALUES (?, ?, ?, 'LOCAL', true) RETURNING id", Integer.class, EMAIL, USERNAME, hash);
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        customerId = jdbc.queryForObject("INSERT INTO users (email, username, display_name, password_hash, "
                + "auth_method, active, organization_id) VALUES (?, 'carol', 'Carol Customer', ?, 'LOCAL', true, ?) "
                + "RETURNING id", Integer.class, CUSTOMER_EMAIL, hash, organizationId);
        Metrics.addRegistry(lockouts);
    }

    @AfterEach
    void clean() {
        Metrics.removeRegistry(lockouts);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        jdbc.execute("DELETE FROM user_roles");
        jdbc.execute("DELETE FROM user_permissions");
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
    }

    // ===== tokens_valid_after (V140) =====

    @Test
    void tokensValidAfterIsReadPerRequestAndNeverMovesBack() {
        OffsetDateTime later = OffsetDateTime.of(2026, 10, 1, 12, 0, 5, 0, ZoneOffset.UTC);
        OffsetDateTime earlier = later.minusMinutes(5);

        assertThat(userRepository.findAccessStateById(userId)).hasValueSatisfying(state -> {
            assertThat(state.getTokensValidAfter()).isNull();
            assertThat(state.getMustChangePassword()).isFalse();
        });
        assertThat(userRepository.markTokensValidAfter(userId, later)).isEqualTo(1);
        userRepository.markTokensValidAfter(userId, earlier);

        assertThat(userRepository.findAccessStateById(userId)).hasValueSatisfying(state ->
                assertThat(state.getTokensValidAfter().toInstant()).isEqualTo(later.toInstant()));
        assertThat(userRepository.findAccessStateById(customerId).orElseThrow().getTokensValidAfter()).isNull();
    }

    @Test
    void firstRunSetupLockIsATransactionScopedAdvisoryLock() {
        org.springframework.transaction.support.TransactionTemplate tx =
                new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        Integer locked = tx.execute(status -> userRepository.lockForFirstRunSetup(AdminUserService.FIRST_RUN_SETUP_LOCK_KEY));
        assertThat(locked).isEqualTo(1);
        // Released with the transaction: nothing is held afterwards.
        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'", Integer.class))
                .isZero();
    }

    // ===== /api/auth/login (UnifiedAuthService) =====

    @Test
    void unifiedLoginLocksAfterTheLimitAndThenRefusesTheCorrectPassword() {
        lockAfterLimitThenRefuseCorrectPassword(password -> unifiedLogin(EMAIL, password));
    }

    @Test
    void unifiedLoginByUsernameCountsTowardsTheSameLock() {
        lockAfterLimitThenRefuseCorrectPassword(password -> unifiedLogin(USERNAME, password));
    }

    // ===== /api/v1/admin/login (AdminUserService.authenticate) =====

    @Test
    void adminLoginLocksAfterTheLimitAndThenRefusesTheCorrectPassword() {
        lockAfterLimitThenRefuseCorrectPassword(this::adminLogin);
    }

    @Test
    void successfulLoginResetsTheCount() {
        for (int i = 0; i < MAX - 1; i++) {
            assertRefused(() -> adminLogin(WRONG), INVALID);
        }
        assertThat(failedAttempts()).isEqualTo(MAX - 1);

        LocalLoginResponse response = adminLogin(PASSWORD);

        assertThat(response.getUserId()).isEqualTo(userId);
        assertThat(response.getLastLoginAt()).isNotNull();
        assertThat(failedAttempts()).isZero();
        assertThat(lockedUntil()).isNull();
        assertThat(jdbc.queryForObject("SELECT last_login_at FROM users WHERE id = ?", OffsetDateTime.class, userId))
                .isNotNull();

        // The count starts again from zero: one short of the limit leaves the account open.
        for (int i = 0; i < MAX - 1; i++) {
            assertRefused(() -> unifiedLogin(EMAIL, WRONG), INVALID);
        }
        assertThat(lockedUntil()).isNull();
        assertThat(unifiedLogin(EMAIL, PASSWORD).getUserId()).isEqualTo(userId);
    }

    @Test
    void lockExpiresAfterTheDurationAndTheCorrectPasswordThenSignsIn() throws InterruptedException {
        lockByWrongPasswords();
        assertRefused(() -> adminLogin(PASSWORD), LOCKED);

        expireLock();

        assertThat(adminLogin(PASSWORD).getUserId()).isEqualTo(userId);
        assertThat(failedAttempts()).isZero();
        assertThat(lockedUntil()).isNull();
    }

    @Test
    void afterTheLockRunsOutOneWrongPasswordCountsAsTheFirstAndDoesNotLockAgain() throws InterruptedException {
        lockByWrongPasswords();
        expireLock();

        assertRefused(() -> adminLogin(WRONG), INVALID);

        assertThat(failedAttempts()).isOne();
        assertThat(lockedUntil()).isNull();
        // It takes the full limit again to lock.
        for (int i = 1; i < MAX; i++) {
            assertRefused(() -> adminLogin(WRONG), INVALID);
        }
        assertLockedForAboutTheDuration();
    }

    // ===== Writers of the counter =====

    @Test
    void savingAUserLoadedBeforeTheLockDoesNotClearIt() {
        User stale = userRepository.findById(userId).orElseThrow();
        lockByWrongPasswords();
        OffsetDateTime until = lockedUntil();

        stale.setDisplayName("Renamed meanwhile");
        userRepository.save(stale);

        assertThat(jdbc.queryForObject("SELECT display_name FROM users WHERE id = ?", String.class, userId))
                .isEqualTo("Renamed meanwhile");
        assertThat(failedAttempts()).isEqualTo(MAX);
        assertThat(lockedUntil()).isEqualTo(until);
        assertRefused(() -> adminLogin(PASSWORD), LOCKED);
    }

    // ===== Sign-in audit and lock visibility =====

    @Test
    void aCustomerLockIsAnAccountLockedRowAndALockedAttemptIsAccountLockedOncePerMinute() {
        for (int i = 0; i < MAX; i++) {
            assertRefused(() -> unifiedLogin(CUSTOMER_EMAIL, WRONG), INVALID);
        }

        // The wrong passwords are one sign_in_failed row (one a minute per account); the one that reached
        // the limit also writes auth.account_locked, in the organization's trail, as CertPing.
        await().atMost(Duration.ofSeconds(10)).until(() -> lockedRows(customerId).size() == 1
                && failureCodes().equals(List.of("INVALID_CREDENTIALS")));
        Map<String, Object> locked = jdbc.queryForMap("SELECT visibility, organization_id, actor_type, "
                + "resource_type, resource_id, resource_name, summary, details->'attributes'->>'attempts' AS attempts "
                + "FROM audit_events WHERE event = 'auth.account_locked' AND resource_id = ?", customerId);
        assertThat(locked).containsEntry("visibility", "CUSTOMER").containsEntry("organization_id", organizationId)
                .containsEntry("actor_type", "SYSTEM").containsEntry("resource_type", "USER")
                .containsEntry("resource_id", (long) customerId).containsEntry("resource_name", null)
                .containsEntry("summary", "a member's account was locked after " + MAX + " failed sign-ins")
                .containsEntry("attempts", Integer.toString(MAX));
        assertThat(lockouts.counter("certping.auth.lockouts", "staff", "false").count()).isEqualTo(1.0);

        // Within the same minute the locked refusal is throttled; past it, it is written as ACCOUNT_LOCKED.
        assertRefused(() -> unifiedLogin(CUSTOMER_EMAIL, PASSWORD), LOCKED);
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(2))
                .until(() -> failureCodes().equals(List.of("INVALID_CREDENTIALS")));
        auditClock.advance(Duration.ofMinutes(1).plusSeconds(1));
        assertRefused(() -> unifiedLogin(CUSTOMER_EMAIL, PASSWORD), LOCKED);

        await().atMost(Duration.ofSeconds(10))
                .until(() -> failureCodes().equals(List.of("INVALID_CREDENTIALS", "ACCOUNT_LOCKED")));
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_user_id FROM audit_events "
                + "WHERE event = 'auth.sign_in_failed' AND occurred_at >= ?", Integer.class, testStart))
                .containsExactly(customerId);
        assertThat(lockedRows(customerId)).hasSize(1);
    }

    @Test
    void aStaffLockIsCountedAsStaffAndIsAnInternalAccountLockedRow() {
        lockByWrongPasswords();

        assertThat(lockouts.counter("certping.auth.lockouts", "staff", "true").count()).isEqualTo(1.0);
        // Staff have no customer trail: the lock is an internal row, written by CertPing, for support.
        await().atMost(Duration.ofSeconds(10)).until(() -> lockedRows(userId).size() == 1);
        Map<String, Object> locked = jdbc.queryForMap("SELECT visibility, organization_id, actor_type, actor_job, "
                + "resource_type, resource_id, resource_ref, details->'attributes'->>'attempts' AS attempts "
                + "FROM audit_events WHERE event = 'auth.account_locked' AND resource_id = ?", userId);
        assertThat(locked).containsEntry("visibility", "INTERNAL").containsEntry("organization_id", null)
                .containsEntry("actor_type", "SYSTEM").containsEntry("actor_job", "account-lockout")
                .containsEntry("resource_type", "USER").containsEntry("resource_id", (long) userId)
                .containsEntry("resource_ref", Integer.toString(userId))
                .containsEntry("attempts", Integer.toString(MAX));
    }

    @Test
    void aFailureWhileTheLockRunsIsCountedButNeitherMovesTheLockNorStartsAnother() throws InterruptedException {
        for (int i = 0; i < MAX; i++) {
            assertRefused(() -> unifiedLogin(CUSTOMER_EMAIL, WRONG), INVALID);
        }
        await().atMost(Duration.ofSeconds(10)).until(() -> lockedRows(customerId).size() == 1);
        OffsetDateTime until = lockedUntil(customerId);
        assertThat(until).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
        Thread.sleep(50);

        // A sign-in that read the account before the lock committed still counts its wrong password.
        for (int i = 1; i <= 3; i++) {
            LoginAttemptService.FailedLogin failed = loginAttemptService.recordFailure(customerId).orElseThrow();
            assertThat(failed.attempts()).isEqualTo(MAX + i);
            assertThat(failed.lockedUntil()).isEqualTo(until);
            assertThat(failed.lockStarted()).isFalse();
        }

        assertThat(lockedUntil(customerId)).isEqualTo(until);
        assertThat(jdbc.queryForObject("SELECT failed_login_attempts FROM users WHERE id = ?", Integer.class,
                customerId)).isEqualTo(MAX + 3);
        // Still locked by the one lock: the correct password is refused, and no second lock is recorded.
        assertRefused(() -> unifiedLogin(CUSTOMER_EMAIL, PASSWORD), LOCKED);
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(2))
                .until(() -> lockedRows(customerId).size() == 1);
        assertThat(lockouts.counter("certping.auth.lockouts", "staff", "false").count()).isEqualTo(1.0);
    }

    @Test
    void wrongPasswordsRacingTheLockAreAllCountedAndStartExactlyOneLockedRow() throws Exception {
        jdbc.update("UPDATE users SET failed_login_attempts = ? WHERE id = ?", MAX - 1, customerId);

        List<Object> outcomes = runInParallel(() -> {
            try {
                unifiedLogin(CUSTOMER_EMAIL, WRONG);
                return "signed in";
            } catch (UnauthorizedException e) {
                return e.getMessage();
            }
        });

        // Whichever wrong passwords were checked before the lock committed are counted; only one started it.
        assertThat(outcomes).isSubsetOf(INVALID, LOCKED).contains(INVALID);
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(10))
                .until(() -> lockedRows(customerId).size() == 1);
        assertThat(lockouts.counter("certping.auth.lockouts", "staff", "false").count()).isEqualTo(1.0);
        assertThat(lockedUntil(customerId)).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
    }

    // ===== Concurrency =====

    @Test
    void parallelFailuresAreEachCountedOnceAndOnlyOneStartsTheLock() throws Exception {
        List<Object> outcomes = runInParallel(() -> loginAttemptService.recordFailure(userId).orElseThrow());

        assertThat(failedAttempts()).isEqualTo(PARALLEL);
        List<LoginAttemptService.FailedLogin> failures = outcomes.stream()
                .map(LoginAttemptService.FailedLogin.class::cast).toList();
        List<LoginAttemptService.FailedLogin> started = failures.stream()
                .filter(LoginAttemptService.FailedLogin::lockStarted).toList();
        assertThat(started).hasSize(1);
        assertThat(started.get(0).attempts()).isEqualTo(MAX);
        // The failures after it are counted under the lock it started, which none of them moves.
        OffsetDateTime until = started.get(0).lockedUntil();
        assertThat(failures).filteredOn(f -> f.attempts() > MAX)
                .hasSize(PARALLEL - MAX)
                .allSatisfy(f -> assertThat(f.lockedUntil()).isEqualTo(until));
        assertThat(lockedUntil()).isEqualTo(until);
        assertLockedForAboutTheDuration();
    }

    @Test
    void moreParallelWrongPasswordsThanPoolConnectionsAreAllCountedWithoutWaitingForOne() throws Exception {
        long started = System.nanoTime();
        List<Object> outcomes = runInParallel(() -> {
            try {
                unifiedLogin(EMAIL, WRONG);
                return "signed in";
            } catch (UnauthorizedException e) {
                return e.getMessage();
            } catch (RuntimeException e) {
                return e.getClass().getSimpleName();
            }
        });
        Duration took = Duration.ofNanos(System.nanoTime() - started);

        // A sign-in that read the row before the lock committed is counted; one that read it after is
        // refused uncounted, with the answer any wrong password gets. So the column holds at least the
        // limit and at most one per attempt, and none may have waited out the pool's 3s connection timeout.
        assertThat(outcomes).isSubsetOf(INVALID, LOCKED);
        assertThat(failedAttempts()).isBetween(MAX, PARALLEL);
        assertThat(took).isLessThan(Duration.ofSeconds(3));
        assertLockedForAboutTheDuration();
        assertRefused(() -> adminLogin(PASSWORD), LOCKED);
    }

    // ===== Helpers =====

    private void lockAfterLimitThenRefuseCorrectPassword(Consumer<String> login) {
        for (int i = 1; i < MAX; i++) {
            assertRefused(() -> login.accept(WRONG), INVALID);
            assertThat(failedAttempts()).isEqualTo(i);
            assertThat(lockedUntil()).isNull();
        }

        assertRefused(() -> login.accept(WRONG), INVALID);
        assertThat(failedAttempts()).isEqualTo(MAX);
        assertLockedForAboutTheDuration();

        // Locked: the correct password is refused, by either endpoint, before it is checked.
        assertRefused(() -> login.accept(PASSWORD), LOCKED);
        assertRefused(() -> adminLogin(PASSWORD), LOCKED);
        assertRefused(() -> unifiedLogin(EMAIL, PASSWORD), LOCKED);
        assertThat(failedAttempts()).isEqualTo(MAX);
    }

    private void lockByWrongPasswords() {
        for (int i = 0; i < MAX; i++) {
            assertRefused(() -> adminLogin(WRONG), INVALID);
        }
        assertLockedForAboutTheDuration();
    }

    private LocalLoginResponse adminLogin(String password) {
        return adminUserService.authenticate(LocalLoginRequest.builder().username(USERNAME).password(password).build());
    }

    private LocalLoginResponse unifiedLogin(String identifier, String password) {
        return unifiedAuthService.login(UnifiedLoginRequest.builder().identifier(identifier).password(password).build());
    }

    private static void assertRefused(Runnable login, String message) {
        assertThatThrownBy(login::run).isInstanceOf(UnauthorizedException.class).hasMessage(message);
    }

    private List<Object> runInParallel(Callable<Object> attempt) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(PARALLEL);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Object>> futures = new ArrayList<>();
            for (int i = 0; i < PARALLEL; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return attempt.call();
                }));
            }
            start.countDown();
            List<Object> outcomes = new ArrayList<>();
            for (Future<Object> future : futures) {
                outcomes.add(future.get(60, TimeUnit.SECONDS));
            }
            return outcomes;
        } finally {
            pool.shutdownNow();
        }
    }

    private void assertLockedForAboutTheDuration() {
        OffsetDateTime until = lockedUntil();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        assertThat(until).isNotNull();
        assertThat(until).isAfter(now);
        assertThat(until).isBeforeOrEqualTo(now.plusSeconds(LOCK_SECONDS));
    }

    private int failedAttempts() {
        return jdbc.queryForObject("SELECT failed_login_attempts FROM users WHERE id = ?", Integer.class, userId);
    }

    private OffsetDateTime lockedUntil() {
        return lockedUntil(userId);
    }

    private OffsetDateTime lockedUntil(int id) {
        return jdbc.queryForObject("SELECT locked_until FROM users WHERE id = ?", OffsetDateTime.class, id);
    }

    /**
     * The {@code auth.account_locked} rows for account {@code id}. By account: a staff lock's row is queued,
     * so one from the test before can land after the cleanup.
     */
    private List<Map<String, Object>> lockedRows(int id) {
        return jdbc.queryForList("SELECT * FROM audit_events WHERE event = 'auth.account_locked' AND resource_id = ?",
                (long) id);
    }

    /** The reason codes of the sign_in_failed rows written since this test began, oldest first. */
    private List<String> failureCodes() {
        return jdbc.queryForList("SELECT error_code FROM audit_events WHERE event = 'auth.sign_in_failed' "
                + "AND occurred_at >= ? ORDER BY occurred_at, id", String.class, testStart);
    }

    private void expireLock() {
        jdbc.update("UPDATE users SET locked_until = ? WHERE id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(1), userId);
    }
}
