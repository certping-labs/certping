// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.dto.user.UserDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.entity.User;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Creating, enabling, disabling and deleting a user, and the roles SSO gives at first login, are audited. */
@ExtendWith(MockitoExtension.class)
class UserAccessAuditTest {

    private static final long ORG_ID = 7L;
    private static final Organization ORGANIZATION = Organization.builder().id(ORG_ID).build();

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private RoleMappingService roleMappingService;
    @Mock private com.certmanagement.service.audit.AccessAuditRecorder accessAudit;

    private final Role viewer = Role.builder().id(5L).name("VIEWER").isSystemRole(true).build();

    private AdminUserService adminUsers;
    private UserService users;
    private UserProvisioningService provisioning;

    @BeforeEach
    void setUp() {
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        lenient().when(passwordEncoder.encode(anyString())).thenReturn("hash");
        adminUsers = new AdminUserService(userRepository, mock(OrganizationRepository.class), roleRepository,
                passwordEncoder, mock(JwtTokenProvider.class), mock(RefreshTokenService.class), grantPolicy, mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), accessAudit, org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));
        users = new UserService(userRepository, mock(UserDomainCertRepository.class), mock(AlertRepository.class),
                mock(RefreshTokenService.class),
                mock(ApplicationEventPublisher.class), grantPolicy, accessAudit, new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        provisioning = new UserProvisioningService(userRepository, roleMappingService, accessAudit);
        lenient().when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            if (user.getId() == null) {
                user.setId(21);
            }
            return user;
        });
    }

    @Test
    void createUser_recordsTheInitialRoles() {
        adminUsers.createUser("new", "a-long-password", "new@acme.test", null, ORGANIZATION, new HashSet<>(Set.of(viewer)));

        Object[] created = recorded("memberCreated");
        assertThat(roleNames(created[1])).containsExactly("VIEWER");
        assertThat(created[3]).isEqualTo("LOCAL");
    }

    @Test
    void deleteUser_recordsTheRolesTheUserHeld() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.deleteUserForOrganization(21, ORG_ID);

        assertThat(roleNames(recorded("memberDeleted")[1])).containsExactly("VIEWER");
    }

    @Test
    void disableUser_isRecorded() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.disableUserForOrganization(21, ORG_ID);

        assertThat(roleNames(recorded("memberDisabled")[1])).containsExactly("VIEWER");
    }

    @Test
    void updateThatDisablesTheUser_isRecordedAsDisabled() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("a@acme.test").active(false).build());

        recorded("memberDisabled");
    }

    @Test
    void updateThatEnablesTheUser_isRecordedAsEnabled() {
        User disabled = user();
        disabled.setActive(false);
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(disabled));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("a@acme.test").active(true).build());

        recorded("memberEnabled");
    }

    @Test
    void updateThatLeavesTheActiveFlag_recordsNoAccessChange() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("a@acme.test").active(true).build());

        verifyNoInteractions(accessAudit);
    }

    @Test
    void anEmailChangeIsRecorded() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.updateUserForOrganization(21, ORG_ID,
                UserDto.builder().email("mallory@evil.test").active(true).build());

        recorded("memberEmailChanged");
    }

    @Test
    void anEmailChangeOnlyInLetterCaseIsNotRecorded() {
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user()));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("A@Acme.test").active(true).build());

        verifyNoInteractions(accessAudit);
    }

    @Test
    void firstSsoLogin_recordsTheRolesMappedFromTheIdp() {
        SsoConfig config = SsoConfig.builder().registrationId("org-7-okta-oidc").autoProvisionEnabled(true).build();
        when(roleMappingService.shouldSyncRolesOnFirstLogin(config)).thenReturn(true);
        when(roleMappingService.mapIdpRolesToAppRoles(any(), eq(config))).thenReturn(new HashSet<>(Set.of(viewer)));

        provisioning.findOrProvisionUser(ssoUser(), ORGANIZATION, config);

        Object[] assigned = recorded("ssoRolesAssigned");
        assertThat(roleNames(assigned[1])).containsExactly("VIEWER");
        assertThat(assigned[2]).isEqualTo("IDP_ROLE_MAPPING");
        assertThat(assigned[3]).isEqualTo("org-7-okta-oidc");
    }

    @Test
    void firstSsoLogin_withoutRoleSync_recordsTheDefaultRole() {
        SsoConfig config = SsoConfig.builder().registrationId("org-7-oidc").autoProvisionEnabled(true).build();
        when(roleMappingService.shouldSyncRolesOnFirstLogin(config)).thenReturn(false);
        when(roleMappingService.getDefaultRole(config)).thenReturn(new HashSet<>(Set.of(viewer)));

        provisioning.findOrProvisionUser(ssoUser(), ORGANIZATION, config);

        Object[] assigned = recorded("ssoRolesAssigned");
        assertThat(roleNames(assigned[1])).containsExactly("VIEWER");
        assertThat(assigned[2]).isEqualTo("DEFAULT_ROLE");
    }

    @Test
    void laterSsoLogins_recordNoRoleChange() {
        when(userRepository.findByIdpUserIdAndOrganizationId("idp-1", ORG_ID)).thenReturn(Optional.of(user()));

        provisioning.findOrProvisionUser(ssoUser(), ORGANIZATION, SsoConfig.builder().build());

        verifyNoInteractions(accessAudit);
    }

    @Test
    void deactivatingAnSsoUser_isRecorded() {
        when(userRepository.findById(21)).thenReturn(Optional.of(user()));

        provisioning.deactivateUser(21);

        recorded("memberDisabled");
    }

    // A disable is recorded on the row, so a later sign-in cannot undo it.

    @Test
    void disableUser_marksTheUserDisabled() {
        User user = user();
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user));

        users.disableUserForOrganization(21, ORG_ID);

        assertThat(user.getDisabledAt()).isNotNull();
    }

    @Test
    void updateThatDisablesTheUser_marksTheUserDisabled() {
        User user = user();
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(user));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("a@acme.test").active(false).build());

        assertThat(user.getDisabledAt()).isNotNull();
    }

    @Test
    void updateThatEnablesTheUser_clearsTheDisable() {
        User disabled = user();
        disabled.setActive(false);
        disabled.setDisabledAt(OffsetDateTime.now());
        when(userRepository.findByIdAndOrganizationId(21, ORG_ID)).thenReturn(Optional.of(disabled));

        users.updateUserForOrganization(21, ORG_ID, UserDto.builder().email("a@acme.test").active(true).build());

        assertThat(disabled.getDisabledAt()).isNull();
    }

    @Test
    void deactivatingAnSsoUser_marksTheUserDisabled() {
        User user = user();
        when(userRepository.findById(21)).thenReturn(Optional.of(user));

        provisioning.deactivateUser(21);

        assertThat(user.getDisabledAt()).isNotNull();
    }

    /** The arguments of the one {@code event} call the recorder got, for user 21. */
    private Object[] recorded(String event) {
        List<Object[]> calls = org.mockito.Mockito.mockingDetails(accessAudit).getInvocations().stream()
                .filter(call -> call.getMethod().getName().equals(event))
                .map(call -> call.getArguments())
                .toList();
        assertThat(calls).as("the %s event", event).hasSize(1);
        assertThat(((User) calls.get(0)[0]).getId()).isEqualTo(21);
        return calls.get(0);
    }

    @SuppressWarnings("unchecked")
    private static List<String> roleNames(Object roles) {
        return ((java.util.Collection<Role>) roles).stream().map(Role::getName).sorted().toList();
    }

    private User user() {
        return User.builder().id(21).email("a@acme.test").organization(ORGANIZATION).active(true)
                .roles(new HashSet<>(Set.of(viewer))).permissions(new HashSet<>()).build();
    }

    private static SsoUserInfo ssoUser() {
        return SsoUserInfo.builder().email("a@acme.test").idpUserId("idp-1").build();
    }
}
