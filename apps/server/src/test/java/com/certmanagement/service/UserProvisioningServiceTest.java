// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.entity.User;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserProvisioningServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleMappingService roleMappingService;

    @Mock private com.certmanagement.service.audit.AccessAuditRecorder accessAuditRecorder;

    @InjectMocks private UserProvisioningService service;

    private Organization org() {
        return Organization.builder().id(42L).domain("acme.com").name("Acme").build();
    }

    private SsoUserInfo userInfo() {
        return SsoUserInfo.builder()
                .email("a@acme.com")
                .idpUserId("idp-1")
                .roles(Set.of("Admin"))
                .groups(Set.of("g"))
                .build();
    }

    @Test
    void findOrProvisionUser_existingByIdpUserId_updatesLastLogin() {
        User existing = User.builder().id(5).email("a@acme.com").idpUserId("idp-1").build();
        when(userRepository.findByIdpUserIdAndOrganizationId("idp-1", 42L))
                .thenReturn(Optional.of(existing));
        when(userRepository.save(existing)).thenReturn(existing);

        User result = service.findOrProvisionUser(userInfo(), org(), SsoConfig.builder().build());

        assertThat(result).isEqualTo(existing);
        assertThat(existing.getLastLoginAt()).isNotNull();
        verify(userRepository).save(existing);
    }

    @Test
    void findOrProvisionUser_existingByEmail_linksIdpUserIdIfMissing() {
        User existing = User.builder().id(6).email("a@acme.com").build(); // idpUserId null
        when(userRepository.findByIdpUserIdAndOrganizationId("idp-1", 42L))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCaseAndOrganizationId("a@acme.com", 42L))
                .thenReturn(Optional.of(existing));
        when(userRepository.save(existing)).thenReturn(existing);

        User result = service.findOrProvisionUser(userInfo(), org(), SsoConfig.builder().build());

        assertThat(result.getIdpUserId()).isEqualTo("idp-1");
    }

    /**
     * A stored identifier that differs from the asserted one means the IdP now presents this person
     * differently — typically an email-format NameID after a rename, or a move to a stable
     * attribute. Adopting it stops the next login falling back to the email match again.
     */
    @Test
    void findOrProvisionUser_existingByEmailWithDifferentIdpId_relinksToAssertedIdentity() {
        User existing = User.builder().id(6).email("a@acme.com").idpUserId("old-subject").build();
        when(userRepository.findByIdpUserIdAndOrganizationId("idp-1", 42L))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCaseAndOrganizationId("a@acme.com", 42L))
                .thenReturn(Optional.of(existing));
        when(userRepository.save(existing)).thenReturn(existing);

        User result = service.findOrProvisionUser(userInfo(), org(), SsoConfig.builder().build());

        assertThat(result.getIdpUserId()).isEqualTo("idp-1");
    }

    @Test
    void findOrProvisionUser_autoProvisionDisabled_throwsForbidden() {
        when(userRepository.findByIdpUserIdAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCaseAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        SsoConfig cfg = SsoConfig.builder().autoProvisionEnabled(false).build();

        assertThatThrownBy(() -> service.findOrProvisionUser(userInfo(), org(), cfg))
                .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void findOrProvisionUser_provisionsNewUser_withSyncRoles() {
        when(userRepository.findByIdpUserIdAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCaseAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        SsoConfig cfg = SsoConfig.builder().autoProvisionEnabled(true).build();
        Role mapped = Role.builder().id(1L).name("ORG_ADMIN").build();
        when(roleMappingService.shouldSyncRolesOnFirstLogin(cfg)).thenReturn(true);
        when(roleMappingService.mapIdpRolesToAppRoles(any(), eq(cfg))).thenReturn(Set.of(mapped));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(100);
            return u;
        });

        User result = service.findOrProvisionUser(userInfo(), org(), cfg);

        ArgumentCaptor<User> cap = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(cap.capture());
        assertThat(cap.getValue().getEmail()).isEqualTo("a@acme.com");
        assertThat(cap.getValue().getIdpUserId()).isEqualTo("idp-1");
        assertThat(cap.getValue().getActive()).isTrue();
        assertThat(cap.getValue().getRoles()).contains(mapped);
        assertThat(result.getId()).isEqualTo(100);
    }

    @Test
    void findOrProvisionUser_provisionsNewUser_withDefaultRole() {
        when(userRepository.findByIdpUserIdAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCaseAndOrganizationId(any(), any())).thenReturn(Optional.empty());
        SsoConfig cfg = SsoConfig.builder().autoProvisionEnabled(true).build();
        Role def = Role.builder().id(2L).name("VIEWER").build();
        when(roleMappingService.shouldSyncRolesOnFirstLogin(cfg)).thenReturn(false);
        when(roleMappingService.getDefaultRole(cfg)).thenReturn(Set.of(def));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> AdminUserServiceTest.withId(inv.getArgument(0)));

        service.findOrProvisionUser(userInfo(), org(), cfg);

        verify(roleMappingService).getDefaultRole(cfg);
        verify(roleMappingService, never()).mapIdpRolesToAppRoles(any(), any());
    }

    @Test
    void deactivateUser_setsInactiveAndSaves() {
        User user = User.builder().id(5).active(true).build();
        when(userRepository.findById(5)).thenReturn(Optional.of(user));

        service.deactivateUser(5);

        assertThat(user.getActive()).isFalse();
        verify(userRepository).save(user);
    }

    @Test
    void deactivateUser_userNotFound_isNoOp() {
        when(userRepository.findById(anyInt())).thenReturn(Optional.empty());
        service.deactivateUser(99);
        verify(userRepository, never()).save(any());
    }
}
