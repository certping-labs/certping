// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.User;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmailAndOrganizationId(String email, Long organizationId);

    /**
     * Case-insensitive counterpart used by SSO provisioning. Email uniqueness is enforced on
     * LOWER(email), so an assertion whose casing differs from the stored value refers to the same
     * person — an exact match would miss it and fork a second account.
     */
    Optional<User> findByEmailIgnoreCaseAndOrganizationId(String email, Long organizationId);

    Optional<User> findByIdpUserIdAndOrganizationId(String idpUserId, Long organizationId);

    Optional<User> findByEmail(String email);

    @Query("SELECT u.id FROM User u WHERE u.email = :email")
    Optional<Integer> findIdByEmail(@Param("email") String email);

    /**
     * Account state alone, for the per-request check in
     * {@link com.certmanagement.security.JwtAuthenticationFilter}. Loading the entity instead joins
     * three EAGER collections — {@code User.roles}, {@code User.permissions} and
     * {@code Role.permissions} — whose product is hydrated on every authenticated request. The
     * filter reads none of it: roles and permissions come from the token's claims.
     */
    @Query("SELECT u.active AS active, u.isDeleted AS isDeleted FROM User u WHERE u.id = :id")
    Optional<ActivationStateProjection> findActivationStateById(@Param("id") Integer id);

    /**
     * What {@link com.certmanagement.security.JwtAuthenticationFilter} checks on every request: the
     * activation flags, whether a password change is owed, and the instant before which access tokens are
     * refused. One row, no collections.
     */
    @Query("SELECT u.active AS active, u.isDeleted AS isDeleted, u.mustChangePassword AS mustChangePassword, "
            + "u.tokensValidAfter AS tokensValidAfter FROM User u WHERE u.id = :id")
    Optional<UserAccessStateProjection> findAccessStateById(@Param("id") Integer id);

    /**
     * Refuses the user's access tokens issued before {@code at} (never moves the instant back). One
     * statement, so a stale entity cannot undo it.
     */
    @Modifying
    @Transactional
    @NativeQuery("UPDATE users SET tokens_valid_after = GREATEST(COALESCE(tokens_valid_after, CAST(:at AS TIMESTAMPTZ)), "
            + "CAST(:at AS TIMESTAMPTZ)) WHERE id = :userId")
    int markTokensValidAfter(@Param("userId") Integer userId, @Param("at") OffsetDateTime at);

    /** {@link #markTokensValidAfter} for every user who holds or held the role. */
    @Modifying
    @Transactional
    @NativeQuery("UPDATE users SET tokens_valid_after = GREATEST(COALESCE(tokens_valid_after, CAST(:at AS TIMESTAMPTZ)), "
            + "CAST(:at AS TIMESTAMPTZ)) WHERE id IN (SELECT ur.user_id FROM user_roles ur WHERE ur.role_id = :roleId)")
    int markTokensValidAfterForRole(@Param("roleId") Long roleId, @Param("at") OffsetDateTime at);

    /**
     * Serializes first-run setup: a transaction-scoped advisory lock, held until the caller's transaction
     * ends, so two concurrent setup requests cannot both see an empty users table.
     */
    @NativeQuery("SELECT 1 FROM (SELECT pg_advisory_xact_lock(:key)) AS setup_lock")
    Integer lockForFirstRunSetup(@Param("key") long key);

    @Query("SELECT u.id, u.email FROM User u WHERE u.id IN :ids")
    List<Object[]> findIdEmailByIdIn(@Param("ids") java.util.Collection<Integer> ids);

    /**
     * Emails of all active, non-deleted users holding a platform-level role (organization_id IS NULL)
     * — e.g. {@link com.certmanagement.security.Permissions#ROLE_SUPER_ADMIN}. Used to fan out
     * operational alerts to every super admin; org-scoped roles are intentionally excluded.
     */
    @NativeQuery("SELECT DISTINCT u.email FROM users u " +
            "JOIN user_roles ur ON u.id = ur.user_id " +
            "JOIN roles r ON ur.role_id = r.id " +
            "WHERE r.name = :roleName " +
            "AND r.organization_id IS NULL " +
            "AND u.active = true " +
            "AND u.is_deleted = false " +
            "AND ur.is_deleted = false " +
            "AND r.is_deleted = false")
    List<String> findActivePlatformRoleEmails(@Param("roleName") String roleName);

    /**
     * Active users of the organization, other than {@code excludedUserId}, who hold the system role {@code roleName}.
     * {@code fk()} tests the role's organization column itself; a plain {@code r.organization IS NULL} would join
     * organizations (because of its soft-delete restriction) and never match a system role.
     */
    @Query("SELECT COUNT(DISTINCT u.id) FROM User u JOIN u.roles r " +
           "WHERE u.organization.id = :organizationId AND u.id <> :excludedUserId AND u.active = true " +
           "AND r.name = :roleName AND fk(r.organization) IS NULL")
    long countActiveWithSystemRoleInOrganizationExcept(@Param("organizationId") Long organizationId,
                                                       @Param("roleName") String roleName,
                                                       @Param("excludedUserId") Integer excludedUserId);

    boolean existsByEmailAndOrganizationId(String email, Long organizationId);

    // Organization-scoped queries
    List<User> findByOrganizationId(Long organizationId);

    List<User> findByOrganizationIdOrderByUpdatedAtDesc(Long organizationId);

    Optional<User> findByIdAndOrganizationId(Integer id, Long organizationId);

    // Local auth queries
    Optional<User> findByUsername(String username);

    /** Platform Super Admins who work in no organization (FirstOrganizationService). */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name = 'SUPER_ADMIN' AND fk(u.organization) IS NULL")
    List<User> findSuperAdminsWithoutOrganization();

    Optional<User> findByUsernameAndOrganizationId(String username, Long organizationId);

    boolean existsByUsername(String username);

    /**
     * A password sign-in succeeded: clears the failed-login count and any lock, and stamps the sign-in, in
     * one statement. The entity never writes those two columns ({@code updatable = false}), so a stale copy
     * of the user cannot undo a lock or a reset.
     */
    @Modifying
    @Transactional
    @NativeQuery("UPDATE users SET failed_login_attempts = 0, locked_until = NULL, " +
                   "last_login_at = CAST(:now AS TIMESTAMPTZ), updated_at = CAST(:now AS TIMESTAMPTZ) " +
                   "WHERE id = :userId")
    int recordSuccessfulLogin(@Param("userId") Integer userId, @Param("now") OffsetDateTime now);

    /** Clears the failed-login count and any lock (a password reset), in one statement. */
    @Modifying
    @Transactional
    @NativeQuery("UPDATE users SET failed_login_attempts = 0, locked_until = NULL, " +
                   "updated_at = CAST(:now AS TIMESTAMPTZ) WHERE id = :userId")
    int clearFailedLogins(@Param("userId") Integer userId, @Param("now") OffsetDateTime now);

    @Modifying
    @NativeQuery("UPDATE users SET is_deleted = true, updated_at = CURRENT_TIMESTAMP " +
                   "WHERE organization_id = :organizationId AND is_deleted = false")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    @Modifying
    @NativeQuery("UPDATE user_roles SET is_deleted = true WHERE user_id = :userId AND is_deleted = false")
    int softDeleteUserRolesByUserId(@Param("userId") Integer userId);

    @Modifying
    @NativeQuery("UPDATE user_permissions SET is_deleted = true WHERE user_id = :userId AND is_deleted = false")
    int softDeleteUserPermissionsByUserId(@Param("userId") Integer userId);

    @Modifying
    @NativeQuery("UPDATE user_roles SET is_deleted = true WHERE user_id IN (SELECT id FROM users WHERE organization_id = :orgId) AND is_deleted = false")
    int softDeleteUserRolesByOrganizationId(@Param("orgId") Long orgId);

    @Modifying
    @NativeQuery("UPDATE user_permissions SET is_deleted = true WHERE user_id IN (SELECT id FROM users WHERE organization_id = :orgId) AND is_deleted = false")
    int softDeleteUserPermissionsByOrganizationId(@Param("orgId") Long orgId);

    /**
     * The ids {@link #hardDeleteByOrganizationIdAndUpdatedAtBefore} is about to delete, so their audit
     * rows can be pseudonymised first. Unbounded on purpose: one organization's soft-deleted members past
     * retention, which the delete removes in the same statement anyway.
     */
    @NativeQuery("SELECT id FROM users WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND updated_at < :cutoff")
    List<Integer> findPurgeableUserIds(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM users WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND updated_at < :cutoff")
    int hardDeleteByOrganizationIdAndUpdatedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") OffsetDateTime cutoff);

    // Password-hash rotation queries (PasswordHashRotationService). The prefix
    // is the literal `$enc1$<pepperVersion>$` — e.g. `$enc1$v1$` to find every
    // row still encrypted under pepper v1.
    List<User> findByPasswordHashStartingWith(String prefix, Pageable pageable);

    long countByPasswordHashStartingWith(String prefix);
}
