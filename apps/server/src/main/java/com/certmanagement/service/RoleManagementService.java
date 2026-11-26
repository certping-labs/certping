// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.dto.role.RoleDto;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PermissionFeatureMap;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.audit.AccessAuditDetails;
import com.certmanagement.service.audit.AccessAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import static com.certmanagement.security.Permissions.*;

/**
 * Service for managing roles, permissions, and role-permission assignments.
 *
 * <p>Permissions follow feature flags ({@link PermissionFeatureVisibility}): for an organization,
 * permissions of features that are off are left out of every read, roles made only of them are
 * left out of role lists, and every save merges, so hidden permissions already held are kept and
 * none can be added. The organization is the one acted on — the request's, else the role's or the
 * user's — so a super admin working on another organization sees that organization's view.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class RoleManagementService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;
    private final PermissionGrantPolicy grantPolicy;
    private final AccessAuditRecorder accessAudit;
    private final PermissionFeatureVisibility featureVisibility;

    private static final Set<String> SUPER_ADMIN_ALLOWED_PERMISSIONS = Set.of(
            ORGANIZATION_VIEW, ORGANIZATION_MANAGE,
            USERS_VIEW, USERS_CREATE, USERS_MANAGE, USERS_DELETE,
            ROLES_VIEW, ROLES_ASSIGN,
            PERMISSIONS_VIEW,
            AUDIT_VIEW,
            AGENT_DEEP_HEALTH_READ
    );

    // ===== Role CRUD =====

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAll(Sort.by(Sort.Direction.DESC, "updatedAt")).stream()
                .map(this::mapRoleToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles(Long organizationId) {
        List<Role> systemRoles = roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc().stream()
                .filter(this::isVisibleSystemRole)
                .toList();
        List<Role> organizationRoles = organizationId == null
                ? List.of()
                : roleRepository.findByOrganizationIdOrderByUpdatedAtDesc(organizationId).stream()
                .filter(this::isCustomRole)
                .toList();

        Set<Role> allRoles = new LinkedHashSet<>(systemRoles);
        allRoles.addAll(organizationRoles);

        PermissionFeatureVisibility.Hidden hidden = featureVisibility.forOrganization(organizationId);
        return allRoles.stream()
                .filter(role -> !hidden.hidesAll(namesOf(role.getPermissions())))
            .sorted(Comparator.comparing(Role::getUpdatedAt,
                Comparator.nullsLast(Comparator.naturalOrder())).reversed())
                .map(role -> mapRoleToDto(role, hidden))
                .collect(Collectors.toList());
    }

    /**
     * Names of the roles every one of whose permissions is hidden for the organization — system roles
     * and the organization's own — so pickers and saves outside this service (SSO role mapping) can
     * leave them out and keep them.
     */
    @Transactional(readOnly = true)
    public Set<String> roleNamesHiddenFor(Long organizationId) {
        PermissionFeatureVisibility.Hidden hidden = featureVisibility.forOrganization(organizationId);
        if (hidden.disabledFeatureKeys().isEmpty()) {
            return Set.of();
        }
        // Bounded: the fixed catalog of system roles plus one organization's custom roles.
        List<Role> candidates = new ArrayList<>(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc());
        candidates.addAll(roleRepository.findByOrganizationId(organizationId));
        return candidates.stream()
                .filter(hidden::hidesRole)
                .map(Role::getName)
                .collect(Collectors.toUnmodifiableSet());
    }

    @Transactional(readOnly = true)
    public RoleDto getRoleById(Long id, Long organizationId) {
        Role role = resolveVisibleRole(id, organizationId);
        return mapRoleToDto(role, hiddenFor(organizationId, role));
    }

    public RoleDto createRole(CreateRoleRequest request, Long organizationId) {
        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + organizationId));

        String normalizedRoleName = request.getName().trim().toUpperCase(Locale.ROOT);

        Optional<Role> existing = roleRepository.findByNameAndOrganizationIsNull(normalizedRoleName);
        if (existing.isPresent()) {
            throw new BadRequestException("A system role with name '" + normalizedRoleName + "' already exists");
        }

        Optional<Role> organizationExisting = roleRepository.findByNameAndOrganizationId(normalizedRoleName, organizationId);
        if (organizationExisting.isPresent()) {
            throw new BadRequestException("A role with name '" + normalizedRoleName + "' already exists for this organization");
        }

        Set<Permission> resolvedPermissions = request.getPermissionNames() == null || request.getPermissionNames().isEmpty()
                ? Set.of()
                : featureVisibility.forOrganization(organizationId)
                        .mergeKeepingHidden(resolvePermissions(request.getPermissionNames()), Set.of());
        grantPolicy.assertGrantable(grantPolicy.currentCaller(), namesOf(resolvedPermissions));

        Role role = Role.builder()
                .name(normalizedRoleName)
                .description(request.getDescription())
                .organization(organization)
                .isSystemRole(false)
                .permissions(new HashSet<>(resolvedPermissions))
                .build();

        Role saved = roleRepository.save(role);
        accessAudit.roleCreated(saved);
        contextLogger().info("Created custom role: {}", saved.getName());
        return mapRoleToDto(saved, featureVisibility.forOrganization(organizationId));
    }

    public void deleteRole(Long roleId, Long organizationId) {
        Role role = resolveOrganizationOwnedRole(roleId, organizationId);

        if (Boolean.TRUE.equals(role.getIsSystemRole())) {
            throw new BadRequestException("System roles cannot be deleted");
        }

        // Holders' access tokens still name the role; the soft-deleted assignment rows still name them.
        userRepository.markTokensValidAfterForRole(roleId, SessionRevocationService.now());
        int unassignedUsers = roleRepository.softDeleteUserRolesByRoleId(roleId);
        roleRepository.softDeleteRolePermissionsByRoleId(roleId);
        role.setIsDeleted(true);
        roleRepository.save(role);
        List<String> permissions = AccessAuditDetails.permissions(role.getPermissions());
        accessAudit.roleDeleted(role, permissions, unassignedUsers);
        contextLogger().info("Soft-deleted custom role: {}", role.getName());
    }

    // ===== Permission-to-Role Management =====

    public RoleDto updateRolePermissions(Long roleId, Long organizationId, UpdateRolePermissionsRequest request) {
        Role role = resolveOrganizationOwnedRole(roleId, organizationId);
        if (Boolean.TRUE.equals(role.getIsSystemRole())) {
            throw new BadRequestException("System role permissions cannot be modified");
        }

        PermissionFeatureVisibility.Hidden hidden = featureVisibility.forOrganization(role.getOrganization().getId());
        Set<Permission> permissions = hidden.mergeKeepingHidden(
                resolvePermissions(request.getPermissionNames()), role.getPermissions());
        List<String> before = AccessAuditDetails.permissions(role.getPermissions());
        Set<String> added = namesOf(permissions);
        added.removeAll(namesOf(role.getPermissions()));
        if (!added.isEmpty()) {
            PermissionGrantPolicy.Caller caller = grantPolicy.currentCaller();
            grantPolicy.assertGrantable(caller, added);
            grantPolicy.assertNotGrantingToOwnRole(caller, role.getId());
        }
        role.setPermissions(permissions);

        Role saved = roleRepository.save(role);
        List<String> after = AccessAuditDetails.permissions(permissions);
        if (!after.equals(before)) {
            // Every holder's access tokens list the role's old permissions.
            userRepository.markTokensValidAfterForRole(roleId, SessionRevocationService.now());
            accessAudit.rolePermissionsChanged(saved, before, after);
        }
        contextLogger().info("Updated permissions for role '{}': {} permissions", role.getName(), permissions.size());
        return mapRoleToDto(saved, hidden);
    }

    @Transactional(readOnly = true)
    public Set<PermissionDto> getRolePermissions(Long roleId, Long organizationId) {
        Role role = resolveVisibleRole(roleId, organizationId);
        PermissionFeatureVisibility.Hidden hidden = hiddenFor(organizationId, role);

        return role.getPermissions().stream()
                .filter(permission -> !hidden.hides(permission.getName()))
                .map(this::mapPermissionToDto)
                .collect(Collectors.toSet());
    }

    // ===== Role-to-User Assignment =====

    /**
     * Assign roles to a user. Replaces all existing role assignments.
     *
     * <p>The user's individual permission grants ({@code user.permissions}) are NOT modified.
     * Role-derived permissions are surfaced at runtime via
     * {@link User#getEffectivePermissionNames()} (role permissions ∪ user.permissions) — they
     * are not stamped into the user_permissions table.</p>
     *
     * <p>To revoke a single role-derived permission X for a user holding role R = {X, Y, Z}:
     * (1) POST /users/{id}/permissions with {Y, Z} to add them as individual grants;
     * (2) call this method with a role set that excludes R. Purely additive — no deny entries.</p>
     */
    public void assignRolesToUser(Integer userId, Long organizationId, Set<Long> roleIds) {
        User user = loadUserInScope(userId, organizationId);

        Set<Role> requested = new HashSet<>();
        for (Long roleId : roleIds) {
            Role role = resolveAssignableRole(roleId, organizationId);
            requested.add(role);
        }
        // Role pickers leave out roles made only of features that are off, so a save keeps the hidden
        // roles the user holds and refuses to add one.
        Set<Role> roles = hiddenFor(user).mergeRolesKeepingHidden(requested, user.getRoles());

        validatePrivilegedRolePermissionPolicy(roles);
        PermissionGrantPolicy.Caller caller = grantPolicy.currentCaller();
        grantPolicy.assertMayChange(caller, user, user.getActive(), roles);
        Set<Long> currentRoleIds = user.getRoles().stream().map(Role::getId).collect(Collectors.toSet());
        Set<Role> added = roles.stream()
                .filter(role -> !currentRoleIds.contains(role.getId()))
                .collect(Collectors.toSet());
        if (!added.isEmpty()) {
            grantPolicy.assertNotGrantingToSelf(caller, userId);
            grantPolicy.assertAssignable(caller, added);
        }
        Set<Role> heldBefore = new HashSet<>(user.getRoles());
        List<Map<String, Object>> rolesBefore = AccessAuditDetails.roles(user.getRoles());
        Set<Permission> directGrantsAfter = grantPolicy.directGrantsAfterRoleChange(user, roles);
        Set<Permission> droppedDirectGrants = new HashSet<>(user.getPermissions());
        droppedDirectGrants.removeAll(directGrantsAfter);
        user.setPermissions(directGrantsAfter);
        user.setRoles(roles);

        userRepository.save(user);
        List<Map<String, Object>> rolesAfter = AccessAuditDetails.roles(roles);
        if (!rolesAfter.equals(rolesBefore) || !droppedDirectGrants.isEmpty()) {
            // The user's access tokens carry the old roles: refuse them, the next refresh carries the new.
            userRepository.markTokensValidAfter(userId, SessionRevocationService.now());
            List<String> dropped = AccessAuditDetails.permissions(droppedDirectGrants);
            accessAudit.memberRolesChanged(user, heldBefore, roles, dropped);
        }
        contextLogger().info("Assigned {} roles to user {} (individual grants: {} entries)",
                roles.size(), userId, user.getPermissions().size());
    }

    // ===== User Permission Management =====

    @Transactional(readOnly = true)
    public Set<PermissionDto> getUserPermissions(Integer userId, Long organizationId) {
        User user = loadUserInScope(userId, organizationId);

        return visibleDtos(user.getPermissions(), hiddenFor(user));
    }

    public Set<PermissionDto> setUserPermissions(Integer userId, Long organizationId, Set<String> permissionNames) {
        User user = loadUserInScope(userId, organizationId);
        PermissionFeatureVisibility.Hidden hidden = hiddenFor(user);

        Set<Permission> requested = hidden.mergeKeepingHidden(resolvePermissions(permissionNames), user.getPermissions());
        Set<Permission> permissions = grantPolicy.assertDirectGrantsAllowed(grantPolicy.currentCaller(), user, requested);
        replaceDirectGrants(user, permissions);

        contextLogger().info("Set {} direct permissions for user {}", permissions.size(), userId);
        return visibleDtos(permissions, hidden);
    }

    public Set<PermissionDto> addUserPermissions(Integer userId, Long organizationId, Set<String> permissionNames) {
        User user = loadUserInScope(userId, organizationId);
        PermissionFeatureVisibility.Hidden hidden = hiddenFor(user);

        Set<Permission> toAdd = resolvePermissions(permissionNames);
        Set<Permission> requested = new HashSet<>(user.getPermissions());
        requested.addAll(toAdd);
        requested = hidden.mergeKeepingHidden(requested, user.getPermissions());
        Set<Permission> current = grantPolicy.assertDirectGrantsAllowed(grantPolicy.currentCaller(), user, requested);
        replaceDirectGrants(user, current);

        contextLogger().info("Added {} permissions to user {} (total: {})", toAdd.size(), userId, current.size());
        return visibleDtos(current, hidden);
    }

    public Set<PermissionDto> removeUserPermissions(Integer userId, Long organizationId, Set<String> permissionNames) {
        User user = loadUserInScope(userId, organizationId);
        PermissionFeatureVisibility.Hidden hidden = hiddenFor(user);

        Set<Permission> toRemove = resolvePermissions(permissionNames);
        // A hidden permission cannot be seen, so it cannot be removed either: it stays as it is.
        toRemove.removeIf(permission -> hidden.hides(permission.getName()));
        Set<Permission> requested = new HashSet<>(user.getPermissions());
        requested.removeAll(toRemove);
        Set<Permission> current = grantPolicy.assertDirectGrantsAllowed(grantPolicy.currentCaller(), user, requested);
        replaceDirectGrants(user, current);

        contextLogger().info("Removed {} permissions from user {} (remaining: {})",
                toRemove.size(), userId, current.size());
        return visibleDtos(current, hidden);
    }

    // ===== Permission Read =====

    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions() {
        return permissionRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::mapPermissionToDto)
                .collect(Collectors.toList());
    }

    /**
     * What an organization's roles and users can be given: never a platform permission, and an
     * organization-admin permission only when a super admin asks.
     */
    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions(Long organizationId) {
        return offeredToOrganizations(getAllPermissions(), organizationId);
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getPermissionsByResource(String resource) {
        return permissionRepository.findByResourceOrderByCreatedAtDesc(resource).stream()
                .map(this::mapPermissionToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getPermissionsByResource(String resource, Long organizationId) {
        return offeredToOrganizations(getPermissionsByResource(resource), organizationId);
    }

    private List<PermissionDto> offeredToOrganizations(List<PermissionDto> permissions, Long organizationId) {
        PermissionGrantPolicy.Caller caller = grantPolicy.currentCaller();
        PermissionFeatureVisibility.Hidden hidden = featureVisibility.forOrganization(organizationId);
        return permissions.stream()
                .filter(permission -> !PLATFORM_PERMISSIONS.contains(permission.getName()))
                .filter(permission -> grantPolicy.isGrantableBy(caller, permission.getName()))
                .filter(permission -> !hidden.hides(permission.getName()))
                .toList();
    }

    // ===== Helpers =====

    private void replaceDirectGrants(User user, Set<Permission> grants) {
        List<String> before = AccessAuditDetails.permissions(user.getPermissions());
        user.setPermissions(grants);
        userRepository.save(user);
        List<String> after = AccessAuditDetails.permissions(grants);
        if (!after.equals(before)) {
            userRepository.markTokensValidAfter(user.getId(), SessionRevocationService.now());
            accessAudit.memberPermissionsChanged(user, before, after);
        }
    }

    private Set<Permission> resolvePermissions(Set<String> permissionNames) {
        List<Permission> found = permissionRepository.findByNameIn(permissionNames);
        if (found.size() != permissionNames.size()) {
            Set<String> foundNames = found.stream().map(Permission::getName).collect(Collectors.toSet());
            Set<String> missing = permissionNames.stream()
                    .filter(n -> !foundNames.contains(n))
                    .collect(Collectors.toSet());
            throw new BadRequestException("Unknown permissions: " + missing);
        }
        return new HashSet<>(found);
    }

    private Role resolveVisibleRole(Long roleId, Long organizationId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleId));

        if (isSuperAdminRole(role)) {
            if (!isCurrentUserSuperAdmin()) {
                throw new ResourceNotFoundException("Role not found: " + roleId);
            }
            return role;
        }

        if (isRegularSystemRole(role)) {
            return role;
        }

        if (isCustomRole(role) && organizationId != null && organizationId.equals(role.getOrganization().getId())) {
            return role;
        }

        throw new ResourceNotFoundException("Role not found: " + roleId);
    }

    private Role resolveOrganizationOwnedRole(Long roleId, Long organizationId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleId));
        if (role.getOrganization() == null || organizationId == null || !organizationId.equals(role.getOrganization().getId())) {
            throw new ResourceNotFoundException("Role not found: " + roleId);
        }
        return role;
    }

    private Role resolveAssignableRole(Long roleId, Long organizationId) {
        Role role = resolveVisibleRole(roleId, organizationId);
        if (role.getOrganization() != null && !organizationId.equals(role.getOrganization().getId())) {
            throw new AccessDeniedException("Role does not belong to organization: " + roleId);
        }
        return role;
    }

    private User loadUserInScope(Integer userId, Long organizationId) {
        if (organizationId == null) {
            return userRepository.findById(userId)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
        }
        return userRepository.findByIdAndOrganizationId(userId, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId + " for organization: " + organizationId));
    }

    private static Set<String> namesOf(Set<Permission> permissions) {
        return permissions.stream().map(Permission::getName).collect(Collectors.toCollection(HashSet::new));
    }

    private void validatePrivilegedRolePermissionPolicy(Set<Role> roles) {
        for (Role role : roles) {
            if (ROLE_SUPER_ADMIN.equals(role.getName())) {
                ensureRolePermissionsWithin(role, SUPER_ADMIN_ALLOWED_PERMISSIONS);
            }
        }
    }

    private void ensureRolePermissionsWithin(Role role, Set<String> allowedPermissionNames) {
        Set<String> disallowed = role.getPermissions().stream()
                .map(Permission::getName)
                .filter(name -> !allowedPermissionNames.contains(name))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!disallowed.isEmpty()) {
            throw new BadRequestException("Role '" + role.getName() + "' has unsupported permissions: " + disallowed);
        }
    }

    /** The organization whose flags apply to a role: the request's, else the role's own (custom roles). */
    private PermissionFeatureVisibility.Hidden hiddenFor(Long organizationId, Role role) {
        Long flagOrganizationId = organizationId != null ? organizationId
                : role.getOrganization() != null ? role.getOrganization().getId() : null;
        return featureVisibility.forOrganization(flagOrganizationId);
    }

    /** A user's permissions follow the flags of the user's own organization. */
    private PermissionFeatureVisibility.Hidden hiddenFor(User user) {
        return featureVisibility.forOrganization(user.getOrganization() != null ? user.getOrganization().getId() : null);
    }

    private Set<PermissionDto> visibleDtos(Set<Permission> permissions, PermissionFeatureVisibility.Hidden hidden) {
        return permissions.stream()
                .filter(permission -> !hidden.hides(permission.getName()))
                .map(this::mapPermissionToDto)
                .collect(Collectors.toSet());
    }

    private RoleDto mapRoleToDto(Role role) {
        return mapRoleToDto(role, PermissionFeatureVisibility.Hidden.NOTHING);
    }

    private RoleDto mapRoleToDto(Role role, PermissionFeatureVisibility.Hidden hidden) {
        Set<String> permissionNames = role.getPermissions().stream()
                .map(Permission::getName)
                .filter(name -> !hidden.hides(name))
                .collect(Collectors.toSet());

        return RoleDto.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .organizationId(role.getOrganization() != null ? role.getOrganization().getId() : null)
                .isSystemRole(role.getIsSystemRole())
                .permissions(permissionNames)
                .createdAt(role.getCreatedAt())
                .updatedAt(role.getUpdatedAt())
                .build();
    }

    private PermissionDto mapPermissionToDto(Permission permission) {
        return PermissionDto.builder()
                .id(permission.getId())
                .name(permission.getName())
                .resource(permission.getResource())
                .action(permission.getAction())
                .description(permission.getDescription())
                .featureKey(PermissionFeatureMap.featureKeyOf(permission.getName()))
                .build();
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(RoleManagementService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }

    private boolean isCurrentUserSuperAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .anyMatch(a -> ("ROLE_" + ROLE_SUPER_ADMIN).equals(a.getAuthority()));
    }

    private boolean isVisibleSystemRole(Role role) {
        return isRegularSystemRole(role) || (isSuperAdminRole(role) && isCurrentUserSuperAdmin());
    }

    private boolean isRegularSystemRole(Role role) {
        return Boolean.TRUE.equals(role.getIsSystemRole()) && role.getOrganization() == null && !isSuperAdminRole(role);
    }

    private boolean isSuperAdminRole(Role role) {
        return ROLE_SUPER_ADMIN.equals(role.getName());
    }

    private boolean isCustomRole(Role role) {
        return role.getOrganization() != null && !Boolean.TRUE.equals(role.getIsSystemRole());
    }
}
