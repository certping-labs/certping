// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.CreateUserRequest;

import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminUserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private PermissionGrantPolicy grantPolicy;

    @AfterEach
    void cleanupSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void ensureBootstrapSuperAdmin_createsUserWhenMissing() {
        com.certmanagement.service.audit.AccessAuditRecorder accessAudit =
                mock(com.certmanagement.service.audit.AccessAuditRecorder.class);
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), accessAudit, org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminUsername", "super_admin");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminEmail", "super_admin@certping.local");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminPassword", "SuperAdmin@12345");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminDisplayName", "Super Admin");

        Permission permission = Permission.builder().id(10L).name("users:manage").build();
        Role superAdminRole = Role.builder()
                .id(1L)
                .name(Permissions.ROLE_SUPER_ADMIN)
                .permissions(Set.of(permission))
                .build();

        when(userRepository.findByUsername("super_admin")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("super_admin@certping.local")).thenReturn(Optional.empty());
        when(roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN)).thenReturn(Optional.of(superAdminRole));
        when(passwordEncoder.encode("SuperAdmin@12345")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> withId(invocation.getArgument(0)));

        service.ensureBootstrapSuperAdmin();

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        verify(accessAudit).bootstrapSuperAdminCreated(eq(saved), any());
        assertThat(saved.getUsername()).isEqualTo("super_admin");
        assertThat(saved.getEmail()).isEqualTo("super_admin@certping.local");
        assertThat(saved.getMustChangePassword()).isTrue();
        assertThat(saved.getRoleNames()).contains(Permissions.ROLE_SUPER_ADMIN);
        assertThat(saved.getPermissionNames()).isEmpty(); // bootstrap does not stamp individual grants
        assertThat(saved.getEffectivePermissionNames()).contains("users:manage"); // role provides it
    }

    @Test
    void createUserFromRequest_organizationAdminCanAssignOrganizationAdmin() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "organization-admin", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_ORGANIZATION_ADMIN))));

        CreateUserRequest request = CreateUserRequest.builder()
                .username("new-organization-admin")
                .password("Password@12345")
                .email("new-organization-admin@example.com")
                .roleIds(Set.of(100L))
                .build();

        Role organizationAdminRole = Role.builder().id(100L).name(Permissions.ROLE_ORGANIZATION_ADMIN).build();
        when(roleRepository.findAllById(request.getRoleIds())).thenReturn(List.of(organizationAdminRole));
        when(passwordEncoder.encode("Password@12345")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> withId(invocation.getArgument(0)));

        User created = service.createUserFromRequest(request, Organization.builder().id(1L).build());

        assertThat(created).isNotNull();
        assertThat(created.getRoleNames()).contains(Permissions.ROLE_ORGANIZATION_ADMIN);
    }

    @Test
    void createUserFromRequest_generatesUsernameWhenOmitted() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        CreateUserRequest request = CreateUserRequest.builder()
                .password("Password@12345")
                .email("new.user@example.com")
                .build();

        when(userRepository.existsByUsername("new.user")).thenReturn(false);
        when(passwordEncoder.encode("Password@12345")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> withId(invocation.getArgument(0)));

        User created = service.createUserFromRequest(request, Organization.builder().id(1L).build());

        assertThat(created.getUsername()).isEqualTo("new.user");
        assertThat(created.getDisplayName()).isEqualTo("new.user");
    }

    @Test
    void createUserFromRequest_generatesUniqueUsernameSuffixWhenBaseExists() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        CreateUserRequest request = CreateUserRequest.builder()
                .password("Password@12345")
                .email("new.user@example.com")
                .build();

        when(userRepository.existsByUsername("new.user")).thenReturn(true);
        when(userRepository.existsByUsername("new.user-1")).thenReturn(false);
        when(passwordEncoder.encode("Password@12345")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> withId(invocation.getArgument(0)));

        User created = service.createUserFromRequest(request, Organization.builder().id(1L).build());

        assertThat(created.getUsername()).isEqualTo("new.user-1");
    }

    @Test
    void targetsSuperAdminRole_trueWhenSuperAdminRoleAssigned() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        CreateUserRequest request = CreateUserRequest.builder()
                .email("new-super@example.com")
                .roleIds(Set.of(1L))
                .build();
        Role superAdminRole = Role.builder().id(1L).name(Permissions.ROLE_SUPER_ADMIN).build();
        when(roleRepository.findAllById(request.getRoleIds())).thenReturn(List.of(superAdminRole));

        assertThat(service.targetsSuperAdminRole(request)).isTrue();
    }

    @Test
    void targetsSuperAdminRole_falseForNonSuperAdminRoles() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        CreateUserRequest request = CreateUserRequest.builder()
                .email("new-admin@example.com")
                .roleIds(Set.of(100L))
                .build();
        Role orgAdminRole = Role.builder().id(100L).name(Permissions.ROLE_ORGANIZATION_ADMIN).build();
        when(roleRepository.findAllById(request.getRoleIds())).thenReturn(List.of(orgAdminRole));

        assertThat(service.targetsSuperAdminRole(request)).isFalse();
    }

    @Test
    void targetsSuperAdminRole_falseWhenNoRolesRequested() {
        AdminUserService service = new AdminUserService(
                userRepository, organizationRepository, roleRepository, passwordEncoder, jwtTokenProvider, refreshTokenService, grantPolicy, org.mockito.Mockito.mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        CreateUserRequest request = CreateUserRequest.builder()
                .email("no-roles@example.com")
                .build();

        assertThat(service.targetsSuperAdminRole(request)).isFalse();
    }

    /** A user as the database returns it from its first save: with an id. */
    static User withId(User user) {
        if (user.getId() == null) {
            user.setId(500);
        }
        return user;
    }
}
