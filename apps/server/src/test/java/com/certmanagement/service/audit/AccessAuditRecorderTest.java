// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Each access-control event as it is written: its sentence, trail, actor and target, the "+/−" of a role or
 * permission change, and never a member's name or email.
 */
class AccessAuditRecorderTest {

    private static final long ORG_ID = 7L;
    private static final int ADMIN_ID = 5;
    private static final String EMAIL = "alice.member@acme.test";
    private static final String NAME = "Alice Member";

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final AccessAuditRecorder audit = new AccessAuditRecorder(recorder);
    private final Organization acme = Organization.builder().id(ORG_ID).name("Acme").build();
    private final Role admin = Role.builder().id(1L).name("ORGANIZATION_ADMIN").build();
    private final Role viewer = Role.builder().id(2L).name("VIEWER").build();
    private final Role certManager = Role.builder().id(3L).name("CERT_MANAGER").build();
    private User alice;

    @BeforeEach
    void inRequest() {
        GatewayRequestContext.set(ADMIN_ID, String.valueOf(ORG_ID), "req-1", "admin@acme.test");
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        alice = User.builder().id(21).email(EMAIL).displayName(NAME).username("alice").organization(acme)
                .authMethod(User.AuthMethod.LOCAL).roles(Set.of(admin, viewer)).build();
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
    }

    @Test
    void memberCreated() {
        audit.memberCreated(alice, Set.of(viewer, admin), null, "LOCAL", null, AccessAuditRecorder.Actor.REQUEST);

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.created", "Added a member");
        assertThat(row.actorUserId()).isEqualTo(ADMIN_ID);
        assertThat(row.details().changes()).containsExactly(new AuditChange("roles", null, "ORGANIZATION_ADMIN, VIEWER"));
        assertThat(row.details().attributes()).containsEntry("authMethod", "LOCAL");
    }

    @Test
    void aMemberSigningUpIsTheActorOfTheirOwnRow() {
        audit.memberCreated(alice, Set.of(admin), "SOCIAL_SIGNUP", null, "google", AccessAuditRecorder.Actor.MEMBER);

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.created", "Added a member");
        assertThat(row.actorUserId()).isEqualTo(21);
        assertThat(row.authMethod()).isEqualTo("LOCAL");
        assertThat(row.details().attributes()).containsEntry("source", "SOCIAL_SIGNUP").containsEntry("provider", "google");
    }

    @Test
    void theBootstrapAdminIsAPlatformRowCertPingWrote() {
        User boot = User.builder().id(1).email("boot@certping.test").username("boot").build();

        audit.bootstrapSuperAdminCreated(boot, Set.of(Role.builder().id(9L).name("SUPER_ADMIN").build()));

        AuditEventRow row = recorded();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
        assertThat(row.actorJob()).isEqualTo("bootstrap");
        assertThat(row.toString()).doesNotContain("boot@certping.test");
    }

    @Test
    void memberEnabledDisabledAndDeleted() {
        audit.memberEnabled(alice, "EMAIL_VERIFIED", null, AccessAuditRecorder.Actor.MEMBER);
        audit.memberDisabled(alice, alice.getRoles(), null, AccessAuditRecorder.Actor.REQUEST);
        audit.memberDeleted(alice, alice.getRoles());

        List<AuditEventRow> rows = allRecorded();
        assertMemberRow(rows.get(0), "member.enabled", "Re-enabled a member");
        assertThat(rows.get(0).details().attributes()).containsEntry("source", "EMAIL_VERIFIED");
        assertMemberRow(rows.get(1), "member.disabled", "Disabled a member");
        assertThat(rows.get(1).details().attributes()).containsEntry("roles", "ORGANIZATION_ADMIN, VIEWER");
        assertMemberRow(rows.get(2), "member.deleted", "Removed a member");
    }

    @Test
    void anEmailChangeKeepsTheFieldNameOnly() {
        audit.memberEmailChanged(alice);

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.email_changed", "Changed a member's email");
        assertThat(row.details().changes()).containsExactly(new AuditChange("email", null, null));
    }

    @Test
    void aRoleChangeNamesTheRolesAddedAndRemoved() {
        audit.memberRolesChanged(alice, Set.of(admin, viewer), Set.of(viewer, certManager), List.of("dns:manage"));

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.roles_changed", "Changed a member's roles");
        assertThat(row.details().changes()).containsExactly(
                new AuditChange("roles", "ORGANIZATION_ADMIN, VIEWER", "CERT_MANAGER, VIEWER"));
        assertThat(row.details().attributes()).containsEntry("added", "CERT_MANAGER")
                .containsEntry("removed", "ORGANIZATION_ADMIN").containsEntry("droppedDirectPermissions", "dns:manage");
    }

    @Test
    void aPermissionChangeNamesThePermissionsAddedAndRemoved() {
        audit.memberPermissionsChanged(alice, List.of("certs:view"), List.of("certs:view", "dns:manage"));

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.permissions_changed", "Changed a member's permissions");
        assertThat(row.details().attributes()).containsEntry("added", "dns:manage").doesNotContainKey("removed");
    }

    @Test
    void singleSignOnAssigningRolesIsCertPingActing() {
        audit.ssoRolesAssigned(alice, Set.of(viewer), "IDP_ROLE_MAPPING", "org-7-oidc");

        AuditEventRow row = recorded();
        assertMemberRow(row, "member.sso_roles_assigned", "Single sign-on assigned roles to a member");
        assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
        assertThat(row.actorJob()).isEqualTo("sso-provisioning");
        assertThat(row.ipAddress()).isNull();
        assertThat(row.details().attributes()).containsEntry("registrationId", "org-7-oidc");
    }

    @Test
    void aStaffAccountHasNoCustomerTrail() {
        User staff = User.builder().id(2).email("ops@certping.test").roles(Set.of()).build();

        audit.memberDisabled(staff, Set.of(), null, AccessAuditRecorder.Actor.REQUEST);

        assertThat(recorded().visibility()).isEqualTo(AuditVisibility.INTERNAL);
    }

    @Test
    void customRoles() {
        Role editor = Role.builder().id(40L).name("DOMAIN_EDITOR").organization(acme)
                .permissions(Set.of(Permission.builder().name("domains:view").build(),
                        Permission.builder().name("domains:manage").build())).build();

        audit.roleCreated(editor);
        audit.rolePermissionsChanged(editor, List.of("domains:view"), List.of("domains:manage", "domains:view"));
        audit.roleDeleted(editor, List.of("domains:manage", "domains:view"), 3);

        List<AuditEventRow> rows = allRecorded();
        assertThat(rows).extracting(AuditEventRow::event)
                .containsExactly("role.created", "role.permissions_changed", "role.deleted");
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly("Created the role 'DOMAIN_EDITOR'",
                "Changed the permissions of the role 'DOMAIN_EDITOR'", "Deleted the role 'DOMAIN_EDITOR'");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.organizationId()).isEqualTo(ORG_ID);
            assertThat(row.resourceId()).isEqualTo(40L);
            assertThat(row.resourceName()).isEqualTo("DOMAIN_EDITOR");
        });
        assertThat(rows.get(0).details().changes())
                .containsExactly(new AuditChange("permissions", null, "domains:manage, domains:view"));
        assertThat(rows.get(1).details().attributes()).containsEntry("added", "domains:manage");
        assertThat(rows.get(2).details().attributes()).containsEntry("unassignedMembers", "3");
    }

    /** A member row: the trail, the target by id only, and neither the member's name nor email anywhere. */
    private static void assertMemberRow(AuditEventRow row, String event, String summary) {
        assertThat(row.event()).isEqualTo(event);
        assertThat(row.summary()).isEqualTo(summary);
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.resourceType()).isEqualTo("USER");
        assertThat(row.resourceId()).isEqualTo(21L);
        assertThat(row.resourceRef()).isEqualTo("21");
        assertThat(row.resourceName()).isNull();
        assertThat(row.toString()).doesNotContain(EMAIL).doesNotContain(NAME).doesNotContain("alice");
    }

    private AuditEventRow recorded() {
        List<AuditEventRow> rows = allRecorded();
        assertThat(rows).hasSize(1);
        return rows.get(0);
    }

    private List<AuditEventRow> allRecorded() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.atLeastOnce()).record(rows.capture());
        return rows.getAllValues();
    }
}
