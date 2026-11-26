// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.certmanagement.service.cbom.CertificateInventoryChangedEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private UserDomainCertRepository userDomainCertRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private ApplicationEventPublisher eventPublisher;
    @Mock private com.certmanagement.security.PermissionGrantPolicy grantPolicy;
    @Mock private FeatureFlagService featureFlagService;
    @org.mockito.Spy private PermissionFeatureVisibility featureVisibility = new PermissionFeatureVisibility(
            org.mockito.Mockito.mock(FeatureFlagService.class));

    @Mock private com.certmanagement.service.audit.AccessAuditRecorder accessAuditRecorder;

    @InjectMocks
    private UserService userService;

    @Test
    void getUsersByOrganization_hidesPermissionsAndRolesOfDisabledFeatures() {
        Organization organization = Organization.builder().id(5L).name("T").domain("t.example.com").build();
        com.certmanagement.entity.Permission iot = com.certmanagement.entity.Permission.builder()
                .id(1L).name("iot_device:view").build();
        com.certmanagement.entity.Permission read = com.certmanagement.entity.Permission.builder()
                .id(2L).name("certificate:read").build();
        com.certmanagement.entity.Role iotRole = com.certmanagement.entity.Role.builder()
                .id(3L).name("IOT_MANAGER").permissions(new java.util.HashSet<>(java.util.Set.of(iot))).build();
        com.certmanagement.entity.Role viewer = com.certmanagement.entity.Role.builder()
                .id(4L).name("VIEWER").permissions(new java.util.HashSet<>(java.util.Set.of(read, iot))).build();
        User user = User.builder().id(9).email("m@example.com").organization(organization)
                .roles(new java.util.HashSet<>(java.util.Set.of(iotRole, viewer)))
                .permissions(new java.util.HashSet<>(java.util.Set.of(iot, read))).build();
        when(userRepository.findByOrganizationIdOrderByUpdatedAtDesc(5L)).thenReturn(List.of(user));
        org.mockito.Mockito.doReturn(new PermissionFeatureVisibility.Hidden(java.util.Set.of("IOT_DEVICE_MANAGEMENT")))
                .when(featureVisibility).forOrganization(5L);

        var dto = userService.getUsersByOrganization(5L).get(0);

        assertThat(dto.getRoles()).containsExactly("VIEWER");
        assertThat(dto.getPermissions()).containsExactly("certificate:read");
    }

    @Test
    void getUsersByOrganization_withNothingOff_neverReadsRolePermissions() {
        Organization organization = Organization.builder().id(5L).name("T").domain("t.example.com").build();
        com.certmanagement.entity.Role viewer = org.mockito.Mockito.mock(com.certmanagement.entity.Role.class);
        when(viewer.getName()).thenReturn("VIEWER");
        com.certmanagement.entity.Permission read = com.certmanagement.entity.Permission.builder()
                .id(2L).name("certificate:read").build();
        User user = User.builder().id(9).email("m@example.com").organization(organization)
                .roles(new java.util.HashSet<>(java.util.Set.of(viewer)))
                .permissions(new java.util.HashSet<>(java.util.Set.of(read))).build();
        when(userRepository.findByOrganizationIdOrderByUpdatedAtDesc(5L)).thenReturn(List.of(user));
        org.mockito.Mockito.doReturn(new PermissionFeatureVisibility.Hidden(java.util.Set.of()))
                .when(featureVisibility).forOrganization(5L);

        var dto = userService.getUsersByOrganization(5L).get(0);

        assertThat(dto.getRoles()).containsExactly("VIEWER");
        assertThat(dto.getPermissions()).containsExactly("certificate:read");
        org.mockito.Mockito.verify(viewer, org.mockito.Mockito.never()).getPermissions();
    }

    @Test
    void getAllUsers_usesUpdatedAtDescendingSort() {
        User user = User.builder()
                .id(1)
                .email("user@example.com")
            .updatedAt(OffsetDateTime.now())
                .build();
        when(userRepository.findAll(any(Sort.class))).thenReturn(List.of(user));

        userService.getAllUsers();

        ArgumentCaptor<Sort> sortCaptor = ArgumentCaptor.forClass(Sort.class);
        verify(userRepository).findAll(sortCaptor.capture());
        Sort.Order order = sortCaptor.getValue().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC);
    }

    @Test
    void getUsersByOrganization_usesUpdatedAtOrderedRepositoryMethod() {
        Long organizationId = 1L;
        Organization organization = Organization.builder().id(organizationId).name("T1").domain("t1.example.com").build();
        User user = User.builder()
                .id(2)
                .email("organization-user@example.com")
                .organization(organization)
                .build();
        when(userRepository.findByOrganizationIdOrderByUpdatedAtDesc(organizationId)).thenReturn(List.of(user));

        userService.getUsersByOrganization(organizationId);

        verify(userRepository).findByOrganizationIdOrderByUpdatedAtDesc(organizationId);
    }

    @Test
    void deleteUserForOrganization_setsIsDeletedAndDisablesUser() {
        Integer userId = 10;
        Long organizationId = 1L;
        User user = User.builder()
                .id(userId)
                .email("organization-user@example.com")
                .organization(Organization.builder().id(organizationId).build())
                .active(true)
                .isDeleted(false)
                .build();
        when(userRepository.findByIdAndOrganizationId(userId, organizationId)).thenReturn(Optional.of(user));

        userService.deleteUserForOrganization(userId, organizationId);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getIsDeleted()).isTrue();
        assertThat(userCaptor.getValue().getActive()).isFalse();
    }

    @Test
    void deleteUserForOrganization_throwsWhenUserNotFound() {
        Integer userId = 10;
        Long organizationId = 2L;
        when(userRepository.findByIdAndOrganizationId(userId, organizationId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.deleteUserForOrganization(userId, organizationId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void deleteUserForOrganization_cascadesSoftDeleteToJoinTablesAndRelatedEntities() {
        Integer userId = 10;
        Long organizationId = 1L;
        User user = User.builder().id(userId).email("u@t.com").active(true).isDeleted(false).build();
        when(userRepository.findByIdAndOrganizationId(userId, organizationId)).thenReturn(Optional.of(user));

        userService.deleteUserForOrganization(userId, organizationId);

        verify(userRepository).softDeleteUserRolesByUserId(userId);
        verify(userRepository).softDeleteUserPermissionsByUserId(userId);
        verify(userDomainCertRepository).softDeleteByUserId(userId);
        verify(eventPublisher).publishEvent(any(CertificateInventoryChangedEvent.class));
        verify(alertRepository).softDeleteByUserId(userId);
    }

    @Test
    void deleteUser_cascadesSoftDeleteToRelatedEntities() {
        Integer userId = 5;
        User user = User.builder().id(userId).email("a@b.com").active(true).isDeleted(false).build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        userService.deleteUser(userId);

        verify(userRepository).softDeleteUserRolesByUserId(userId);
        verify(userRepository).softDeleteUserPermissionsByUserId(userId);
        verify(userDomainCertRepository).softDeleteByUserId(userId);
        verify(alertRepository).softDeleteByUserId(userId);
    }
}
