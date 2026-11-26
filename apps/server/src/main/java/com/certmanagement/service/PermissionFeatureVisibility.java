// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.PermissionFeatureMap;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Hides the permissions of features that are off for an organization, and the roles made only of
 * them. Reads the organization's disabled features once (a cached batch decision), then answers per
 * permission from {@link PermissionFeatureMap} with no further queries.
 */
@Component
@RequiredArgsConstructor
public class PermissionFeatureVisibility {

    private final FeatureFlagService featureFlagService;

    /**
     * What to hide for an organization.
     *
     * @param organizationId the organization whose flags apply; {@code null} hides nothing (a super
     *                       admin's platform-wide view)
     */
    public Hidden forOrganization(Long organizationId) {
        return organizationId == null ? Hidden.NOTHING : new Hidden(featureFlagService.disabledFeatureKeys(organizationId));
    }

    /** The disabled features of one organization, applied to permission names. */
    public record Hidden(Set<String> disabledFeatureKeys) {

        static final Hidden NOTHING = new Hidden(Set.of());

        /** Whether the permission belongs to a feature that is off. */
        public boolean hides(String permissionName) {
            String featureKey = PermissionFeatureMap.featureKeyOf(permissionName);
            return featureKey != null && disabledFeatureKeys.contains(featureKey);
        }

        /** Whether a role with these permissions is hidden: it has some, and every one is hidden. */
        public boolean hidesAll(Collection<String> permissionNames) {
            return !permissionNames.isEmpty() && permissionNames.stream().allMatch(this::hides);
        }

        /**
         * The permission set to save when a caller who cannot see hidden permissions replaces a set:
         * what they asked for, plus the hidden permissions already held (a save never strips them).
         *
         * @param requested the permissions the caller asked for
         * @param current   the permissions held before the save
         * @return the merged set to persist
         * @throws BadRequestException when the request adds a permission of a feature that is off
         */
        public Set<Permission> mergeKeepingHidden(Set<Permission> requested, Set<Permission> current) {
            Set<String> currentNames = new HashSet<>();
            current.forEach(permission -> currentNames.add(permission.getName()));
            Set<String> addedHidden = new TreeSet<>();
            requested.stream()
                    .map(Permission::getName)
                    .filter(name -> hides(name) && !currentNames.contains(name))
                    .forEach(addedHidden::add);
            if (!addedHidden.isEmpty()) {
                throw new BadRequestException("Permissions " + addedHidden + " aren't available. Ask your CertPing administrator.");
            }
            Set<Permission> merged = new HashSet<>(requested);
            current.stream().filter(permission -> hides(permission.getName())).forEach(merged::add);
            return merged;
        }

        /** Whether the role is hidden: it has permissions and every one belongs to a feature that is off. */
        public boolean hidesRole(Role role) {
            return role.getPermissions() != null
                    && hidesAll(role.getPermissions().stream().map(Permission::getName).toList());
        }

        /**
         * The role set to save when a caller who cannot see hidden roles replaces a user's roles: what
         * they asked for, plus the hidden roles the user already holds (a save never strips them).
         *
         * @param requested the roles the caller asked for
         * @param current   the roles held before the save
         * @return the merged set to persist
         * @throws BadRequestException when the request adds a role made only of features that are off
         */
        public Set<Role> mergeRolesKeepingHidden(Set<Role> requested, Set<Role> current) {
            if (disabledFeatureKeys.isEmpty()) {
                return requested;
            }
            Set<Long> currentIds = current.stream().map(Role::getId).collect(Collectors.toSet());
            Set<String> addedHidden = requested.stream()
                    .filter(role -> !currentIds.contains(role.getId()) && hidesRole(role))
                    .map(Role::getName)
                    .collect(Collectors.toCollection(TreeSet::new));
            if (!addedHidden.isEmpty()) {
                throw new BadRequestException("Roles " + addedHidden + " aren't available. Ask your CertPing administrator.");
            }
            Set<Role> merged = new HashSet<>(requested);
            current.stream().filter(this::hidesRole).forEach(merged::add);
            return merged;
        }

        /**
         * The SSO role mapping (IdP group or role → CertPing role name) to save when a caller who cannot
         * see hidden roles replaces it: what they asked for, plus the stored entries that target a hidden
         * role and that the request does not name (a save never strips them). An entry the request names
         * explicitly is the caller's decision and replaces the stored one.
         *
         * @param requested       the mapping the caller asked for
         * @param current         the stored mapping; empty when there is none
         * @param hiddenRoleNames the names of the roles hidden for the organization
         * @return the merged mapping to persist
         * @throws BadRequestException when the request maps an IdP value to a hidden role it did not
         *                             already map to
         */
        public static Map<String, String> mergeRoleMappingKeepingHidden(Map<String, String> requested,
                                                                        Map<String, String> current,
                                                                        Set<String> hiddenRoleNames) {
            if (hiddenRoleNames.isEmpty()) {
                return requested;
            }
            Set<String> addedHidden = requested.entrySet().stream()
                    .filter(entry -> hiddenRoleNames.contains(entry.getValue())
                            && !Objects.equals(entry.getValue(), current.get(entry.getKey())))
                    .map(Map.Entry::getValue)
                    .collect(Collectors.toCollection(TreeSet::new));
            if (!addedHidden.isEmpty()) {
                throw new BadRequestException("Roles " + addedHidden + " aren't available. Ask your CertPing administrator.");
            }
            Map<String, String> merged = new LinkedHashMap<>(requested);
            current.forEach((idpValue, roleName) -> {
                if (hiddenRoleNames.contains(roleName)) {
                    merged.putIfAbsent(idpValue, roleName);
                }
            });
            return merged;
        }
    }
}
