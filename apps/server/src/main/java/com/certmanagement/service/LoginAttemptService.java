// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

/**
 * Counts failed password logins and locks the account once they reach the limit.
 *
 * <p>The count is one UPDATE, so parallel attempts each add exactly one, and it commits in a
 * transaction of its own whatever the caller's does. A lock that has run out is cleared by the next
 * failure, which then counts as the first: an expired lock never re-locks on one more wrong password. A
 * failure while a lock runs is counted but never moves the lock's end.
 */
@Service
public class LoginAttemptService {

    /**
     * Postgres evaluates every SET expression against the row as it was, so both CASEs see the old count
     * and the old lock. RETURNING gives the new ones.
     *
     * <p>A failure while a lock is still running is counted but leaves the lock's end where it is: a sign-in
     * that read the row before the lock committed (or anyone still guessing) must not keep pushing it out.
     * {@code lock_started} is true only for the failure that set this attempt's {@code :lockUntil} and
     * reached the limit with it, so a failure during a running lock never reports a second one.
     */
    private static final String RECORD_FAILURE = """
            UPDATE users SET
                failed_login_attempts = CASE
                    WHEN locked_until IS NOT NULL AND locked_until <= CAST(:now AS TIMESTAMPTZ) THEN 1
                    ELSE COALESCE(failed_login_attempts, 0) + 1 END,
                locked_until = CASE
                    WHEN locked_until IS NOT NULL AND locked_until <= CAST(:now AS TIMESTAMPTZ)
                        THEN CASE WHEN 1 >= :maxAttempts THEN CAST(:lockUntil AS TIMESTAMPTZ) ELSE NULL END
                    WHEN locked_until IS NOT NULL AND locked_until > CAST(:now AS TIMESTAMPTZ) THEN locked_until
                    WHEN COALESCE(failed_login_attempts, 0) + 1 >= :maxAttempts THEN CAST(:lockUntil AS TIMESTAMPTZ)
                    ELSE locked_until END,
                updated_at = CAST(:now AS TIMESTAMPTZ)
            WHERE id = :userId
            RETURNING failed_login_attempts, locked_until,
                (failed_login_attempts = :maxAttempts
                    AND locked_until IS NOT DISTINCT FROM CAST(:lockUntil AS TIMESTAMPTZ)) AS lock_started
            """;

    /** What one failed login left on the account. */
    public record FailedLogin(int attempts, OffsetDateTime lockedUntil, boolean lockStarted) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final int maxFailedAttempts;
    private final Duration lockoutDuration;

    public LoginAttemptService(
            NamedParameterJdbcTemplate jdbc,
            @Value("${app.auth.lockout.max-failed-attempts:" + User.MAX_FAILED_ATTEMPTS + "}") int maxFailedAttempts,
            @Value("${app.auth.lockout.duration:PT" + User.LOCKOUT_DURATION_MINUTES + "M}") Duration lockoutDuration) {
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("app.auth.lockout.max-failed-attempts must be at least 1");
        }
        if (lockoutDuration.isNegative() || lockoutDuration.isZero()) {
            throw new IllegalArgumentException("app.auth.lockout.duration must be positive");
        }
        this.jdbc = jdbc;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockoutDuration = lockoutDuration;
    }

    /**
     * Commits one more failed attempt for {@code userId}, locking the account until now plus the lockout
     * duration when the count reaches the limit. The time comes from the application clock, the one
     * {@link User#isLocked()} reads. Empty when the account is gone.
     *
     * <p>{@link FailedLogin#lockStarted()} is true for the attempt that reached the limit only; attempts
     * that raced past it, or came while the lock runs, are counted without moving the lock's end or
     * starting another.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Optional<FailedLogin> recordFailure(Integer userId) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", userId)
                .addValue("maxAttempts", maxFailedAttempts)
                .addValue("lockUntil", now.plus(lockoutDuration))
                .addValue("now", now);
        List<FailedLogin> rows = jdbc.query(RECORD_FAILURE, params, (rs, i) -> new FailedLogin(
                rs.getInt("failed_login_attempts"), rs.getObject("locked_until", OffsetDateTime.class),
                rs.getBoolean("lock_started")));
        return rows.stream().findFirst();
    }
}
