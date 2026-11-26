// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleEmailMapperTest {

    @Mock private UserRepository userRepository;

    private RoleEmailMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new RoleEmailMapper(userRepository, "");
    }

    @Test
    void resolveRolesToEmails_nullRoles_returnsEmpty() {
        assertThat(mapper.resolveRolesToEmails(null, 1L, 2L)).isEmpty();
        verify(userRepository, never()).findEmailsByRoleAndOrganization(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void resolveRolesToEmails_emptyRoles_returnsEmpty() {
        assertThat(mapper.resolveRolesToEmails(Collections.emptyList(), 1L, 2L)).isEmpty();
    }

    @Test
    void resolveRolesToEmails_organization_resolvesAllRoleEmails() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 42L))
                .thenReturn(List.of("admin1@example.com", "admin2@example.com"));
        when(userRepository.findEmailsByRoleAndOrganization("cert_manager", 42L))
                .thenReturn(List.of("cm@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN", "CERT_MANAGER"), 42L, null);

        assertThat(result).containsExactlyInAnyOrder(
                "admin1@example.com", "admin2@example.com", "cm@example.com");
    }

    @Test
    void resolveRolesToEmails_organization_lowercasesAndTrimsRoleName() {
        // Input has whitespace + uppercase; repository is called with normalised form.
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 5L))
                .thenReturn(List.of("admin@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("  ORGANIZATION_ADMIN  "), 5L, null);

        assertThat(result).containsExactly("admin@example.com");
        verify(userRepository).findEmailsByRoleAndOrganization("organization_admin", 5L);
    }

    @Test
    void resolveRolesToEmails_organization_skipsBlankAndNullRoles() {
        when(userRepository.findEmailsByRoleAndOrganization("cert_manager", 5L))
                .thenReturn(List.of("cm@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                java.util.Arrays.asList(null, "", "  ", "CERT_MANAGER"), 5L, null);

        assertThat(result).containsExactly("cm@example.com");
        // Blank/null skipped — only cert_manager queried
        verify(userRepository).findEmailsByRoleAndOrganization("cert_manager", 5L);
        verify(userRepository, never()).findEmailsByRoleAndOrganization("", 5L);
    }

    @Test
    void resolveRolesToEmails_organization_deduplicatesEmailsAcrossRoles() {
        // A user with both roles → email appears in both queries; result must dedup.
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L))
                .thenReturn(List.of("dual@example.com", "admin@example.com"));
        when(userRepository.findEmailsByRoleAndOrganization("cert_manager", 1L))
                .thenReturn(List.of("dual@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN", "CERT_MANAGER"), 1L, null);

        assertThat(result).hasSize(2)
                .containsExactlyInAnyOrder("dual@example.com", "admin@example.com");
    }

    @Test
    void resolveRolesToEmails_organizationRole_lookupFails_isARetryableFailureNotNobody() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L))
                .thenThrow(new RuntimeException("db timeout"));

        assertThatThrownBy(() -> mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN", "CERT_MANAGER"), 1L, 2L))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED));
        verify(userRepository, never()).findEmailByUserId(anyLong());
    }

    @Test
    void resolveRolesToEmails_organization_noEmailsForAnyRole_fallsBackToRequestingUser() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L))
                .thenReturn(List.of()); // empty
        when(userRepository.findEmailByUserId(77L))
                .thenReturn(Optional.of("fallback@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN"), 1L, 77L);

        assertThat(result).containsExactly("fallback@example.com");
    }

    @Test
    void resolveRolesToEmails_organization_noEmailsAndNoUserId_returnsEmpty() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L))
                .thenReturn(List.of());

        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN"), 1L, null);

        assertThat(result).isEmpty();
        verify(userRepository, never()).findEmailByUserId(org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void resolveRolesToEmails_userWithoutOrganization_orgNull_returnsUserEmail() {
        when(userRepository.findEmailByUserId(9L)).thenReturn(Optional.of("user9@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("SOME_ROLE"), null, 9L);

        assertThat(result).containsExactly("user9@example.com");
        // Without an organization the role lookup is skipped entirely.
        verify(userRepository, never()).findEmailsByRoleAndOrganization(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void resolveRolesToEmails_userWithoutOrganization_lookupFails_isARetryableFailureNotNobody() {
        when(userRepository.findEmailByUserId(9L)).thenThrow(new RuntimeException("db down"));

        assertThatThrownBy(() -> mapper.resolveRolesToEmails(List.of("SOME_ROLE"), null, 9L))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED));
    }

    @Test
    void resolveRolesToEmails_organizationFallbackUser_lookupFails_isARetryableFailure() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L)).thenReturn(List.of());
        when(userRepository.findEmailByUserId(2L)).thenThrow(new RuntimeException("db down"));

        assertThatThrownBy(() -> mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 1L, 2L))
                .isInstanceOf(RetryableNotificationException.class);
    }

    @Test
    void resolveRolesToEmails_userWithoutOrganization_userNotFound_returnsEmpty() {
        when(userRepository.findEmailByUserId(9L)).thenReturn(Optional.empty());

        List<String> result = mapper.resolveRolesToEmails(
                List.of("SOME_ROLE"), null, 9L);

        assertThat(result).isEmpty();
    }

    @Test
    void resolveRolesToEmails_orgAndUserBothNull_returnsEmpty() {
        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN"), null, null);

        assertThat(result).isEmpty();
        verify(userRepository, never()).findActivePlatformRoleEmails(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void resolveRolesToEmails_platformRole_resolvesActiveSuperAdmins() {
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN"))
                .thenReturn(List.of("ops1@example.com", "ops2@example.com"));

        List<String> result = mapper.resolveRolesToEmails(List.of("  super_admin "), null, null);

        assertThat(result).containsExactly("ops1@example.com", "ops2@example.com");
        verify(userRepository, never()).findEmailsByRoleAndOrganization(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void resolveRolesToEmails_platformRoleWithOrganization_staysOrganizationScoped() {
        // An organization in the event keeps the lookup inside it: no platform fan-out.
        when(userRepository.findEmailsByRoleAndOrganization("super_admin", 3L)).thenReturn(List.of());

        List<String> result = mapper.resolveRolesToEmails(List.of("SUPER_ADMIN"), 3L, null);

        assertThat(result).isEmpty();
        verify(userRepository, never()).findActivePlatformRoleEmails(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void resolveRolesToEmails_platformRole_lookupFails_isARetryableFailureNotNobody() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, "owner@example.com");
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN")).thenThrow(new RuntimeException("db down"));

        assertThatThrownBy(() -> withBootstrap.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .isInstanceOfSatisfying(RetryableNotificationException.class, e -> {
                    assertThat(e.getReasonCode()).isEqualTo(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED);
                    assertThat(e.getRetryAfter()).isPositive();
                    assertThat(e.getCause()).hasMessage("db down");
                });
    }

    @Test
    void resolveRolesToEmails_platformRole_noActiveSuperAdmin_fallsBackToBootstrapAddress() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, " owner@example.com ");
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN")).thenReturn(List.of());

        assertThat(withBootstrap.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .containsExactly("owner@example.com");
    }

    @Test
    void resolveRolesToEmails_platformRole_onlySeedPlaceholder_fallsBackToBootstrapAddress() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, "owner@example.com");
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN"))
                .thenReturn(List.of("super_admin@certping.local"));

        assertThat(withBootstrap.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .containsExactly("owner@example.com");
    }

    @Test
    void resolveRolesToEmails_platformRole_superAdminsResolve_bootstrapAddressNotAdded() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, "owner@example.com");
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN")).thenReturn(List.of("ops@example.com"));

        assertThat(withBootstrap.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .containsExactly("ops@example.com");
    }

    @Test
    void resolveRolesToEmails_platformRole_bootstrapUnsetOrPlaceholder_resolvesNobody() {
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN")).thenReturn(List.of());

        for (String bootstrap : Arrays.asList(null, "", "  ", "SUPER_ADMIN@certping.local")) {
            assertThat(new RoleEmailMapper(userRepository, bootstrap)
                    .resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null)).as(String.valueOf(bootstrap)).isEmpty();
        }
    }

    @Test
    void resolveRolesToEmails_unknownRoleWithoutContext_doesNotUseBootstrapAddress() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, "owner@example.com");

        assertThat(withBootstrap.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), null, null)).isEmpty();
        verify(userRepository, never()).findActivePlatformRoleEmails(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void resolveRolesToEmails_platformRoleWithOrganization_doesNotUseBootstrapAddress() {
        RoleEmailMapper withBootstrap = new RoleEmailMapper(userRepository, "owner@example.com");
        when(userRepository.findEmailsByRoleAndOrganization("super_admin", 3L)).thenReturn(List.of());

        assertThat(withBootstrap.resolveRolesToEmails(List.of("SUPER_ADMIN"), 3L, null)).isEmpty();
    }

    @Test
    void addressesPlatformRole_onlyWithoutOrganizationOrUser() {
        assertThat(RoleEmailMapper.addressesPlatformRole(List.of(" super_admin "), null, null)).isTrue();
        assertThat(RoleEmailMapper.addressesPlatformRole(Arrays.asList(null, "SUPER_ADMIN"), null, null)).isTrue();
        assertThat(RoleEmailMapper.addressesPlatformRole(List.of("SUPER_ADMIN"), 3L, null)).isFalse();
        assertThat(RoleEmailMapper.addressesPlatformRole(List.of("SUPER_ADMIN"), null, 9L)).isFalse();
        assertThat(RoleEmailMapper.addressesPlatformRole(List.of("ORGANIZATION_ADMIN"), null, null)).isFalse();
        assertThat(RoleEmailMapper.addressesPlatformRole(null, null, null)).isFalse();
    }

    @Test
    void resolveRolesToEmails_platformRole_dropsSeedPlaceholderAndBlanks() {
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN"))
                .thenReturn(Arrays.asList("Super_Admin@certping.local", " ", null, " ops@example.com "));

        assertThat(mapper.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .containsExactly("ops@example.com");
    }

    @Test
    void resolveRolesToEmails_platformRole_nullResult_returnsEmpty() {
        when(userRepository.findActivePlatformRoleEmails("SUPER_ADMIN")).thenReturn(null);

        assertThat(mapper.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null)).isEmpty();
    }

    @Test
    void resolveRolesToEmails_repoReturnsNull_treatedAsEmpty() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 1L))
                .thenReturn(null);
        when(userRepository.findEmailByUserId(2L)).thenReturn(Optional.of("fb@example.com"));

        List<String> result = mapper.resolveRolesToEmails(
                List.of("ORGANIZATION_ADMIN"), 1L, 2L);

        assertThat(result).containsExactly("fb@example.com");
    }

    @Test
    void resolveRolesToEmails_backwardCompatOverload_delegates() {
        when(userRepository.findEmailsByRoleAndOrganization("cert_manager", 1L))
                .thenReturn(List.of("cm@example.com"));

        List<String> result = mapper.resolveRolesToEmails(List.of("CERT_MANAGER"), 1L);

        assertThat(result).containsExactly("cm@example.com");
    }

    @Test
    void includeUserAddsAnActiveMemberOnce() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 7L))
                .thenReturn(List.of("admin@example.com", "Member@Example.com"));
        when(userRepository.findEmailByUserIdInOrganization(9L, 7L)).thenReturn(Optional.of("member@example.com"));

        List<String> result = mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 7L, 9L, true);

        assertThat(result).containsExactly("admin@example.com", "Member@Example.com");
    }

    @Test
    void includeUserAddsAMemberWhoIsNotAnAdmin() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 7L))
                .thenReturn(List.of("admin@example.com"));
        when(userRepository.findEmailByUserIdInOrganization(9L, 7L)).thenReturn(Optional.of("member@example.com"));

        List<String> result = mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 7L, 9L, true);

        assertThat(result).containsExactly("admin@example.com", "member@example.com");
    }

    @Test
    void includeUserSkipsAnExMember() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 7L))
                .thenReturn(List.of("admin@example.com"));
        when(userRepository.findEmailByUserIdInOrganization(9L, 7L)).thenReturn(Optional.empty());

        List<String> result = mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 7L, 9L, true);

        assertThat(result).containsExactly("admin@example.com");
        verify(userRepository, never()).findEmailByUserId(anyLong());
    }

    @Test
    void includeUserWithNoAdminsNeverFallsBackToAnExMember() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 7L)).thenReturn(List.of());
        when(userRepository.findEmailByUserIdInOrganization(9L, 7L)).thenReturn(Optional.empty());

        assertThat(mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 7L, 9L, true)).isEmpty();
        verify(userRepository, never()).findEmailByUserId(anyLong());
    }

    @Test
    void includeUserThatFailsToLookUpIsRetryable() {
        when(userRepository.findEmailsByRoleAndOrganization("organization_admin", 7L))
                .thenReturn(List.of("admin@example.com"));
        when(userRepository.findEmailByUserIdInOrganization(9L, 7L)).thenThrow(new IllegalStateException("db down"));

        assertThatThrownBy(() -> mapper.resolveRolesToEmails(List.of("ORGANIZATION_ADMIN"), 7L, 9L, true))
                .isInstanceOf(RetryableNotificationException.class);
    }
}
