// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Writes the access-control events of the audit trail: members added, re-enabled, disabled, removed, their
 * email, roles and permissions changed, roles single sign-on assigned, and custom roles created, deleted and
 * changed.
 *
 * <p>Each is written in the change's own transaction ({@link AuditRecorder#record}, which requires one), so
 * it commits and rolls back with the change.
 *
 * <p>A member is never named in a row: it is referenced by its user id, its name is rendered when the
 * row is read ({@link AuditEventType#rendersTargetWhenRead()}), and an email change is kept as the field name
 * only. Roles and permissions are named; they are the organization's own vocabulary, not personal data.
 *
 * <p>Who acted comes from the request, except where CertPing acts (single sign-on provisioning, the
 * bootstrap account: the system). A member with no organization (platform
 * staff) has no customer trail: their rows are internal ({@link AuditEvents#platformOnly}).
 */
@Component
public class AccessAuditRecorder {

    /** The job single sign-on provisioning acts as. */
    static final String SSO_PROVISIONING_JOB = "sso-provisioning";
    /** The job creating the bootstrap super admin at startup acts as. */
    static final String BOOTSTRAP_JOB = "bootstrap";

    private final AuditRecorder recorder;

    public AccessAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    /** Who acted on a member. */
    public enum Actor {
        /** The signed-in user of the request. */
        REQUEST,
        /** The member, on their own account, before they hold a token. */
        MEMBER,
        /** CertPing, provisioning a member through single sign-on. */
        SSO_PROVISIONING
    }

    // ── Members ──────────────────────────────────────────────────────────

    /**
     * {@code member} was added with {@code roles}.
     *
     * @param source     how they were added; null for an admin adding them
     * @param authMethod how they sign in, e.g. {@code LOCAL}; null when not set
     * @param provider   the identity provider they came from, or null
     */
    public void memberCreated(User member, Collection<Role> roles, String source, String authMethod, String provider,
                              Actor actor) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "source", source);
        put(attributes, "authMethod", authMethod);
        put(attributes, "provider", provider);
        write(member, actor, AuditEventType.MEMBER_CREATED, memberSubject(member)
                .changes(added("roles", roleNames(roles))).attributes(attributes));
    }

    /** The bootstrap super admin was created at startup: a platform row, CertPing acting. */
    public void bootstrapSuperAdminCreated(User member, Collection<Role> roles) {
        try (AuditScope scope = AuditScope.system(BOOTSTRAP_JOB, null)) {
            recorder.record(AuditEvents.platformOnly(AuditEventType.MEMBER_CREATED, memberSubject(member)
                    .changes(added("roles", roleNames(roles))).attributes(Map.of("authMethod", "LOCAL"))
                    .build()));
        }
    }

    /** {@code member} was re-enabled; {@code source} says how when it was not an admin. */
    public void memberEnabled(User member, String source, String provider, Actor actor) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "source", source);
        put(attributes, "provider", provider);
        write(member, actor, AuditEventType.MEMBER_ENABLED, memberSubject(member).attributes(attributes));
    }

    /** {@code member}, who held {@code roles}, was disabled; {@code source} {@code SSO} when the IdP removed them. */
    public void memberDisabled(User member, Collection<Role> roles, String source, Actor actor) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "source", source);
        put(attributes, "roles", joined(roleNames(roles)));
        write(member, actor, AuditEventType.MEMBER_DISABLED, memberSubject(member).attributes(attributes));
    }

    /** {@code member}, who held {@code roles}, was removed. */
    public void memberDeleted(User member, Collection<Role> roles) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "roles", joined(roleNames(roles)));
        write(member, Actor.REQUEST, AuditEventType.MEMBER_DELETED, memberSubject(member).attributes(attributes));
    }

    /** A platform super admin ({@code member}) made an organization their working organization. */
    public void memberOrganizationChanged(User member) {
        write(member, Actor.REQUEST, AuditEventType.MEMBER_ORGANIZATION_CHANGED, memberSubject(member));
    }

    /** An administrator removed {@code member}'s second factor so they can sign in and enroll again. */
    public void memberMfaReset(User member) {
        write(member, Actor.REQUEST, AuditEventType.MEMBER_MFA_RESET, memberSubject(member));
    }

    /** {@code member}'s email changed: kept as the field name only, never an address. */
    public void memberEmailChanged(User member) {
        write(member, Actor.REQUEST, AuditEventType.MEMBER_EMAIL_CHANGED, memberSubject(member)
                .changes(List.of(new AuditChange("email", null, null))));
    }

    /** {@code member}'s roles changed; {@code droppedDirectPermissions}, the direct grants the change removed. */
    public void memberRolesChanged(User member, Collection<Role> before, Collection<Role> after,
                                   Collection<String> droppedDirectPermissions) {
        List<String> was = roleNames(before);
        List<String> now = roleNames(after);
        Map<String, String> attributes = difference(was, now);
        put(attributes, "droppedDirectPermissions", joined(sorted(droppedDirectPermissions)));
        write(member, Actor.REQUEST, AuditEventType.MEMBER_ROLES_CHANGED, memberSubject(member)
                .changes(changed("roles", was, now)).attributes(attributes));
    }

    /** {@code member}'s direct permission grants changed from {@code before} to {@code after}. */
    public void memberPermissionsChanged(User member, Collection<String> before, Collection<String> after) {
        List<String> was = sorted(before);
        List<String> now = sorted(after);
        write(member, Actor.REQUEST, AuditEventType.MEMBER_PERMISSIONS_CHANGED, memberSubject(member)
                .changes(changed("permissions", was, now)).attributes(difference(was, now)));
    }

    /**
     * Single sign-on provisioned {@code member} with {@code roles} at their first sign-in, CertPing acting.
     *
     * @param source {@code IDP_ROLE_MAPPING} or {@code DEFAULT_ROLE}
     */
    public void ssoRolesAssigned(User member, Collection<Role> roles, String source, String registrationId) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "source", source);
        put(attributes, "registrationId", registrationId);
        write(member, Actor.SSO_PROVISIONING, AuditEventType.MEMBER_SSO_ROLES_ASSIGNED, memberSubject(member)
                .changes(added("roles", roleNames(roles))).attributes(attributes));
    }

    // ── Roles ────────────────────────────────────────────────────────────

    /** The custom role {@code role} was created with its permissions. */
    public void roleCreated(Role role) {
        writeRole(role, AuditEventType.ROLE_CREATED, roleSubject(role)
                .changes(added("permissions", sorted(AccessAuditDetails.permissions(role.getPermissions())))));
    }

    /** The custom role {@code role}, with {@code permissions}, was deleted and unassigned from members. */
    public void roleDeleted(Role role, Collection<String> permissions, int unassignedMembers) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "permissions", joined(sorted(permissions)));
        attributes.put("unassignedMembers", Integer.toString(unassignedMembers));
        writeRole(role, AuditEventType.ROLE_DELETED, roleSubject(role).attributes(attributes));
    }

    /** The custom role {@code role}'s permissions changed from {@code before} to {@code after}. */
    public void rolePermissionsChanged(Role role, Collection<String> before, Collection<String> after) {
        List<String> was = sorted(before);
        List<String> now = sorted(after);
        writeRole(role, AuditEventType.ROLE_PERMISSIONS_CHANGED, roleSubject(role)
                .changes(changed("permissions", was, now)).attributes(difference(was, now)));
    }

    // ── Writing ──────────────────────────────────────────────────────────

    private void write(User member, Actor actor, AuditEventType type, AuditSubject.AuditSubjectBuilder subject) {
        Long organizationId = organizationOf(member);
        AuditSubject built = subject.organizationId(organizationId).build();
        Supplier<AuditEventRow> row = () -> organizationId == null ? AuditEvents.platformOnly(type, built)
                : AuditEvents.success(type, built);
        recorder.record(as(member, actor, row));
    }

    private void writeRole(Role role, AuditEventType type, AuditSubject.AuditSubjectBuilder subject) {
        Long organizationId = role.getOrganization() != null ? role.getOrganization().getId() : null;
        AuditSubject built = subject.organizationId(organizationId).build();
        recorder.record(organizationId == null ? AuditEvents.platformOnly(type, built)
                : AuditEvents.success(type, built));
    }

    private static AuditEventRow as(User member, Actor actor, Supplier<AuditEventRow> row) {
        return switch (actor) {
            case REQUEST -> row.get();
            case MEMBER -> {
                try (AuditScope scope = AuditScope.user(member.getId(), organizationOf(member),
                        member.getAuthMethod() == null ? null : member.getAuthMethod().name(), false)) {
                    yield row.get();
                }
            }
            case SSO_PROVISIONING -> {
                try (AuditScope scope = AuditScope.system(SSO_PROVISIONING_JOB, organizationOf(member))) {
                    yield row.get();
                }
            }
        };
    }

    /** A member target: its numeric id only, never a name or an email. */
    private static AuditSubject.AuditSubjectBuilder memberSubject(User member) {
        return AuditSubject.builder().resourceId(member.getId().longValue()).resourceRef(member.getId().toString());
    }

    private static AuditSubject.AuditSubjectBuilder roleSubject(Role role) {
        return AuditSubject.builder().resourceId(role.getId()).name(role.getName());
    }

    private static Long organizationOf(User member) {
        return member.getOrganization() != null ? member.getOrganization().getId() : null;
    }

    private static List<String> roleNames(Collection<Role> roles) {
        if (roles == null) {
            return List.of();
        }
        return AccessAuditDetails.roles(roles).stream().map(role -> String.valueOf(role.get("name"))).toList();
    }

    private static List<String> sorted(Collection<String> names) {
        return names == null ? List.of() : names.stream().sorted().toList();
    }

    private static List<AuditChange> added(String field, List<String> names) {
        return names.isEmpty() ? List.of() : List.of(new AuditChange(field, null, joined(names)));
    }

    private static List<AuditChange> changed(String field, List<String> before, List<String> after) {
        return before.equals(after) ? List.of() : List.of(new AuditChange(field, joined(before), joined(after)));
    }

    /** The {@code added} and {@code removed} names, "+/−" of a change; each left out when empty. */
    private static Map<String, String> difference(List<String> before, List<String> after) {
        Set<String> added = new LinkedHashSet<>(after);
        before.forEach(added::remove);
        Set<String> removed = new LinkedHashSet<>(before);
        after.forEach(removed::remove);
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "added", joined(new ArrayList<>(added)));
        put(attributes, "removed", joined(new ArrayList<>(removed)));
        return attributes;
    }

    private static String joined(List<String> names) {
        return names.isEmpty() ? null : String.join(", ", names);
    }

    private static void put(Map<String, String> attributes, String name, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(name, value);
        }
    }
}
