// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;

import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How roles and permissions appear in the audit rows of access changes. Sorted, so two rows compare
 * line by line; a role carries its id because a custom role may share a system role's name.
 */
public final class AccessAuditDetails {

    private AccessAuditDetails() {}

    public static List<Map<String, Object>> roles(Collection<Role> roles) {
        return roles.stream()
                .sorted(Comparator.comparing(Role::getName).thenComparing(Role::getId, Comparator.nullsFirst(Long::compare)))
                .map(AccessAuditDetails::role)
                .toList();
    }

    public static Map<String, Object> role(Role role) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("id", role.getId());
        summary.put("name", role.getName());
        return summary;
    }

    public static List<String> permissions(Collection<Permission> permissions) {
        return permissions.stream().map(Permission::getName).sorted().toList();
    }
}
