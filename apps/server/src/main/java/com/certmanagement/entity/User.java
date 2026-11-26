// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(exclude = {"roles", "permissions"})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false)
    private String email;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = true)
    private Organization organization;

    @Column(name = "idp_user_id")
    private String idpUserId;

    // ===== Local Auth Fields =====

    @Column(unique = true)
    private String username;

    @Column(name = "password_hash")
    private String passwordHash;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "must_change_password")
    @Builder.Default
    private Boolean mustChangePassword = false;

    // Written only by single-statement updates (LoginAttemptService, UserRepository.recordSuccessfulLogin,
    // clearFailedLogins), never by saving the entity: a User loaded before a lock started must not clear it
    // when saved for an unrelated change.
    @Column(name = "failed_login_attempts", updatable = false)
    @Builder.Default
    private Integer failedLoginAttempts = 0;

    @Column(name = "locked_until", updatable = false)
    private OffsetDateTime lockedUntil;

    // Access tokens issued before this are refused. Written only by UserRepository.markTokensValidAfter*
    // (single statements), for the same reason as the lockout columns above.
    @Column(name = "tokens_valid_after", insertable = false, updatable = false)
    private OffsetDateTime tokensValidAfter;

    @Column(name = "auth_method")
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private AuthMethod authMethod = AuthMethod.SSO;

    // ===== End Local Auth Fields =====

    @Builder.Default
    private Boolean active = true;

    /** Set when an admin or the IdP switches the user off. */
    @Column(name = "disabled_at")
    private OffsetDateTime disabledAt;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "last_login_at")
    private OffsetDateTime lastLoginAt;

    @Column(name = "provisioned_at")
    private OffsetDateTime provisionedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Individual permission grants for this user — additive on top of role-derived permissions.
     *
     * <p>This set is NOT populated when a role is assigned. Role-derived permissions are
     * surfaced at runtime via {@link #getEffectivePermissionNames()}, which returns the
     * union (role.permissions) ∪ (user.permissions). This field is reserved for permissions
     * granted to the user explicitly via POST /users/{id}/permissions, on top of whatever
     * their roles provide.</p>
     *
     * <p>To revoke a single role-derived permission X for a user holding role R = {X, Y, Z}:
     * add {Y, Z} as individual grants, then reassign the user without R. Purely additive —
     * no deny entries are stored.</p>
     *
     * <p>Historical rows from before this model change are preserved as individual grants;
     * their effective behavior is identical to the prior copy-on-assign model.</p>
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_permissions",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now(ZoneOffset.UTC);
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
        if (isDeleted == null) {
            isDeleted = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }

    /**
     * Get names of permissions individually granted to this user (the user_permissions table).
     *
     * <p><b>Does NOT include role-derived permissions.</b> For authorization decisions and JWT
     * claims, callers should use {@link #getEffectivePermissionNames()} instead. This method is
     * for cases where the admin UI needs to distinguish individual grants from role-derived ones.</p>
     */
    public Set<String> getPermissionNames() {
        Set<String> names = new HashSet<>();
        for (Permission permission : permissions) {
            names.add(permission.getName());
        }
        return names;
    }

    /**
     * Effective permissions = direct grants + permissions inherited from assigned roles.
     */
    public Set<String> getEffectivePermissionNames() {
        Set<String> names = getPermissionNames();
        for (Role role : roles) {
            if (role.getPermissions() == null) {
                continue;
            }
            for (Permission permission : role.getPermissions()) {
                names.add(permission.getName());
            }
        }
        return names;
    }

    public Set<String> getRoleNames() {
        Set<String> roleNames = new HashSet<>();
        for (Role role : roles) {
            roleNames.add(role.getName());
        }
        return roleNames;
    }

    public boolean isLocalUser() {
        return authMethod == AuthMethod.LOCAL;
    }

    public boolean isLocked() {
        return lockedUntil != null && OffsetDateTime.now(ZoneOffset.UTC).isBefore(lockedUntil);
    }

    public boolean isDisabled() {
        return disabledAt != null;
    }

    /** An admin or the IdP switches the user off; signing in cannot undo it. */
    public void disable() {
        active = false;
        disabledAt = OffsetDateTime.now(ZoneOffset.UTC);
    }

    /** Only an admin enable lifts a disable. */
    public void enable() {
        active = true;
        disabledAt = null;
    }

    public enum AuthMethod {
        LOCAL, SSO
    }

    /**
     * Default for {@code app.auth.lockout.max-failed-attempts}: consecutive failed logins before the
     * account is temporarily locked. Counted by {@code LoginAttemptService}.
     */
    public static final int MAX_FAILED_ATTEMPTS = 5;
    /** Default for {@code app.auth.lockout.duration}, in minutes: how long the lock lasts. */
    public static final int LOCKOUT_DURATION_MINUTES = 15;
}
