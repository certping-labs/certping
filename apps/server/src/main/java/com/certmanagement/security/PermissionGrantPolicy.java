// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static com.certmanagement.security.Permissions.ORGANIZATION_ADMIN_ONLY_PERMISSIONS;
import static com.certmanagement.security.Permissions.PLATFORM_PERMISSIONS;
import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * The ceiling on what a caller may hand out, and on whom they may manage.
 *
 * <p>Grants: role creation and edits, role assignment, direct permission grants and user creation
 * check here that
 * <ul>
 *   <li>a platform permission ({@link Permissions#PLATFORM_PERMISSIONS}) is granted only by a super admin;</li>
 *   <li>an organization-admin permission ({@link Permissions#ORGANIZATION_ADMIN_ONLY_PERMISSIONS}) comes
 *       only with the ORGANIZATION_ADMIN role, which only an organization admin assigns, unless a super
 *       admin grants it;</li>
 *   <li>any other permission is granted only by a caller who holds it;</li>
 *   <li>no one but a super admin adds grants to themselves or to a role they hold.</li>
 * </ul>
 *
 * <p>Targets: every change to an existing user (profile and email, enabling, disabling, deleting,
 * roles, direct permissions) checks here that, unless the caller is a super admin,
 * <ul>
 *   <li>the target belongs to the caller's organization;</li>
 *   <li>an organization admin is managed only by another organization admin;</li>
 *   <li>every permission the target holds is one the caller holds;</li>
 *   <li>the organization keeps at least one active organization admin.</li>
 * </ul>
 *
 * <p>Organization: changing the organization itself is left to a super admin or an organization
 * admin of that organization ({@link #mayAdministerOrganization}).
 *
 * <p>"Holds" means what the database grants the caller now, not what the token says: the database
 * is always current, so a token issued before a demotion cannot mint grants that outlive it, and a
 * permission added since the token was issued (a migration, a role edit) is held at once. A super
 * admin, and an organization admin, must carry the role in the token and in the database, so a
 * role removed mid-session stops counting before the token expires.
 */
@Component
@RequiredArgsConstructor
public class PermissionGrantPolicy {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final JwtTokenProvider jwtTokenProvider;

    /** Who is acting, as far as the grant and target rules care. */
    public record Caller(@Nullable Integer userId, @Nullable Long organizationId, boolean superAdmin,
                         boolean organizationAdmin, Set<String> heldPermissions, Set<Long> roleIds) {

        static final Caller NOBODY = new Caller(null, null, false, false, Set.of(), Set.of());
    }

    public Caller currentCaller() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Integer userId = GatewayRequestContext.getUserId();
        if (authentication == null || authentication.getAuthorities() == null || userId == null) {
            return Caller.NOBODY;
        }
        return userRepository.findById(userId)
                .map(user -> callerFrom(user, authentication))
                .orElse(Caller.NOBODY);
    }

    /** For permissions added directly to a user or to a custom role. */
    public void assertGrantable(Caller caller, Collection<String> permissionNames) {
        if (caller.superAdmin() || permissionNames.isEmpty()) {
            return;
        }
        Set<String> platform = permissionNames.stream()
                .filter(PLATFORM_PERMISSIONS::contains)
                .collect(Collectors.toCollection(TreeSet::new));
        if (!platform.isEmpty()) {
            throw new AccessDeniedException("Only a super admin can grant platform permissions: " + platform);
        }
        Set<String> adminOnly = permissionNames.stream()
                .filter(ORGANIZATION_ADMIN_ONLY_PERMISSIONS::contains)
                .collect(Collectors.toCollection(TreeSet::new));
        if (!adminOnly.isEmpty()) {
            throw new AccessDeniedException(
                    "These permissions come only with the ORGANIZATION_ADMIN role: " + adminOnly);
        }
        assertHeld(caller, permissionNames);
    }

    /** Whether {@code caller} may add {@code permissionName} to a custom role or grant it directly. */
    public boolean isGrantableBy(Caller caller, String permissionName) {
        return caller.superAdmin()
                || (!PLATFORM_PERMISSIONS.contains(permissionName)
                    && !ORGANIZATION_ADMIN_ONLY_PERMISSIONS.contains(permissionName));
    }

    /**
     * For roles assigned to a user. The SUPER_ADMIN system role is assigned only by a super admin,
     * and the ORGANIZATION_ADMIN system role only by an organization admin; the latter is the one
     * way to hand out {@link Permissions#ORGANIZATION_ADMIN_ONLY_PERMISSIONS}.
     */
    public void assertAssignable(Caller caller, Collection<Role> roles) {
        if (caller.superAdmin()) {
            return;
        }
        Set<String> permissionNames = new HashSet<>();
        for (Role role : roles) {
            if (isSystemRole(role, ROLE_SUPER_ADMIN)) {
                throw new AccessDeniedException("Only a super admin can assign the SUPER_ADMIN role");
            }
            boolean organizationAdminRole = isOrganizationAdminRole(role);
            if (organizationAdminRole && !caller.organizationAdmin()) {
                throw new AccessDeniedException("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            }
            role.getPermissions().stream()
                    .map(Permission::getName)
                    .filter(name -> !organizationAdminRole || !ORGANIZATION_ADMIN_ONLY_PERMISSIONS.contains(name))
                    .forEach(permissionNames::add);
        }
        assertGrantable(caller, permissionNames);
    }

    /**
     * For a change to {@code target}'s direct grants; returns the grants to store in place of
     * {@code requested}. The ORGANIZATION_ADMIN role supplies
     * {@link Permissions#ORGANIZATION_ADMIN_ONLY_PERMISSIONS}, so for a target who holds it they
     * are dropped rather than granted: stored beside the role, they would outlive a demotion. Every
     * grant the target does not already have is checked as a grant.
     */
    public Set<Permission> assertDirectGrantsAllowed(Caller caller, User target, Collection<Permission> requested) {
        assertMayManage(caller, target);
        Set<Permission> stored = holdsOrganizationAdmin(target.getRoles())
                ? withoutOrganizationAdminOnly(requested)
                : new HashSet<>(requested);
        Set<String> added = stored.stream().map(Permission::getName).collect(Collectors.toCollection(HashSet::new));
        added.removeAll(target.getPermissionNames());
        if (!added.isEmpty()) {
            assertNotGrantingToSelf(caller, target.getId());
            assertGrantable(caller, added);
        }
        return stored;
    }

    /**
     * The direct grants {@code target} keeps once their roles become {@code rolesAfter}. Beside the
     * ORGANIZATION_ADMIN role, or once it is taken away, a direct
     * {@link Permissions#ORGANIZATION_ADMIN_ONLY_PERMISSIONS} grant is removed.
     */
    public Set<Permission> directGrantsAfterRoleChange(User target, Collection<Role> rolesAfter) {
        if (holdsOrganizationAdmin(target.getRoles()) || holdsOrganizationAdmin(rolesAfter)) {
            return withoutOrganizationAdminOnly(target.getPermissions());
        }
        return new HashSet<>(target.getPermissions());
    }

    /** For a change that adds roles or permissions to {@code targetUserId}. */
    public void assertNotGrantingToSelf(Caller caller, Integer targetUserId) {
        if (!caller.superAdmin() && caller.userId() != null && caller.userId().equals(targetUserId)) {
            throw new AccessDeniedException("Cannot grant roles or permissions to yourself");
        }
    }

    /** For a change that adds permissions to the role {@code roleId}. */
    public void assertNotGrantingToOwnRole(Caller caller, Long roleId) {
        if (!caller.superAdmin() && caller.roleIds().contains(roleId)) {
            throw new AccessDeniedException("Cannot add permissions to a role you hold");
        }
    }

    /**
     * For a change to the organization itself (its settings, its active flag, deleting it, purging
     * its soft-deleted records): a super admin, or an organization admin of that organization.
     */
    public boolean mayAdministerOrganization(Caller caller, @Nullable Long organizationId) {
        return caller.superAdmin()
                || (caller.organizationAdmin() && organizationId != null && organizationId.equals(caller.organizationId()));
    }

    /** {@link #mayAdministerOrganization(Caller, Long)} for the current caller, for {@code @PreAuthorize}. */
    public boolean mayAdministerOrganization(@Nullable Object organizationId) {
        Long id = OrgResolver.toOrganizationId(organizationId);
        return id != null && mayAdministerOrganization(currentCaller(), id);
    }

    /** For a change to {@code target} that leaves their active flag and roles as they are. */
    public void assertMayManage(Caller caller, User target) {
        assertMayChange(caller, target, target.getActive(), target.getRoles());
    }

    /** For disabling or deleting {@code target}. */
    public void assertMayDeactivate(Caller caller, User target) {
        assertMayChange(caller, target, false, target.getRoles());
    }

    /**
     * For any change to the existing user {@code target}, given their active flag and roles once
     * the change is applied.
     */
    public void assertMayChange(Caller caller, User target, @Nullable Boolean activeAfter, Collection<Role> rolesAfter) {
        if (caller.superAdmin()) {
            return;
        }
        assertWithinReach(caller, target);
        if (isActiveOrganizationAdmin(target.getActive(), target.getRoles())
                && !isActiveOrganizationAdmin(activeAfter, rolesAfter)) {
            assertAnotherOrganizationAdminRemains(target);
        }
    }

    private void assertHeld(Caller caller, Collection<String> permissionNames) {
        Set<String> notHeld = permissionNames.stream()
                .filter(name -> !caller.heldPermissions().contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        if (!notHeld.isEmpty()) {
            throw new AccessDeniedException("Cannot grant permissions the caller does not hold: " + notHeld);
        }
    }

    private void assertWithinReach(Caller caller, User target) {
        Long targetOrganizationId = target.getOrganization() != null ? target.getOrganization().getId() : null;
        if (caller.organizationId() == null || !caller.organizationId().equals(targetOrganizationId)) {
            throw new AccessDeniedException("Cannot manage a user outside your organization");
        }
        if (holdsOrganizationAdmin(target.getRoles()) && !caller.organizationAdmin()) {
            throw new AccessDeniedException("Only an organization admin can manage an organization admin");
        }
        Set<String> notHeld = jwtTokenProvider.effectivePermissions(target, target.getOrganization()).stream()
                .filter(name -> !caller.heldPermissions().contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        if (!notHeld.isEmpty()) {
            throw new AccessDeniedException(
                    "Cannot manage a user who holds permissions the caller does not hold: " + notHeld);
        }
    }

    /**
     * Locks the organization row first, so two concurrent changes cannot each count the other's
     * admin and together leave the organization with none.
     */
    private void assertAnotherOrganizationAdminRemains(User target) {
        Long organizationId = organizationRepository.findByIdForUpdate(target.getOrganization().getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Organization not found: " + target.getOrganization().getId()))
                .getId();
        long others = userRepository.countActiveWithSystemRoleInOrganizationExcept(
                organizationId, ROLE_ORGANIZATION_ADMIN, target.getId());
        if (others == 0) {
            throw new LastOrganizationAdminException();
        }
    }

    private static boolean isActiveOrganizationAdmin(@Nullable Boolean active, Collection<Role> roles) {
        return Boolean.TRUE.equals(active) && holdsOrganizationAdmin(roles);
    }

    private static boolean holdsOrganizationAdmin(Collection<Role> roles) {
        return roles.stream().anyMatch(PermissionGrantPolicy::isOrganizationAdminRole);
    }

    private static boolean isOrganizationAdminRole(Role role) {
        return isSystemRole(role, ROLE_ORGANIZATION_ADMIN);
    }

    private static boolean isSystemRole(Role role, String name) {
        return name.equals(role.getName()) && role.getOrganization() == null;
    }

    private static Set<Permission> withoutOrganizationAdminOnly(Collection<Permission> permissions) {
        return permissions.stream()
                .filter(permission -> !ORGANIZATION_ADMIN_ONLY_PERMISSIONS.contains(permission.getName()))
                .collect(Collectors.toCollection(HashSet::new));
    }

    private Caller callerFrom(User user, Authentication authentication) {
        Set<String> tokenAuthorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        boolean superAdmin = tokenAuthorities.contains(JwtClaims.ROLE_PREFIX + ROLE_SUPER_ADMIN)
                && user.getRoles().stream().anyMatch(role -> isSystemRole(role, ROLE_SUPER_ADMIN));
        boolean organizationAdmin = tokenAuthorities.contains(JwtClaims.ROLE_PREFIX + ROLE_ORGANIZATION_ADMIN)
                && holdsOrganizationAdmin(user.getRoles());
        Set<String> held = jwtTokenProvider.effectivePermissions(user, user.getOrganization());
        Set<Long> roleIds = user.getRoles().stream().map(Role::getId).collect(Collectors.toSet());
        Long organizationId = user.getOrganization() != null ? user.getOrganization().getId() : null;
        return new Caller(user.getId(), organizationId, superAdmin, organizationAdmin, Set.copyOf(held),
                Set.copyOf(roleIds));
    }
}
