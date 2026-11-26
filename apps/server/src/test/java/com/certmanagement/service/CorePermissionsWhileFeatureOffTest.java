// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PermissionGrantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * {@code certificate:deploy} and {@code credential:read} still authorize endpoints their resource's
 * feature does not gate, so they stay listed and grantable with that feature off; the rest of the
 * resource does not, and {@code audit:view} goes with AUDIT_LOGS.
 */
@ExtendWith(MockitoExtension.class)
class CorePermissionsWhileFeatureOffTest {

    private static final long ORG_ID = 3L;
    private static final Organization ORGANIZATION = Organization.builder().id(ORG_ID).build();

    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private FeatureFlagService featureFlagService;

    private final Permission certRead = permission(1L, "certificate:read");
    private final Permission certDeploy = permission(2L, "certificate:deploy");
    private final Permission credentialRead = permission(3L, "credential:read");
    private final Permission credentialCreate = permission(4L, "credential:create");
    private final Permission auditView = permission(5L, "audit:view");
    private final List<Permission> catalogue = List.of(certRead, certDeploy, credentialRead, credentialCreate, auditView);

    private RoleManagementService service;

    @BeforeEach
    void setUp() {
        service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository,
                userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(featureFlagService));
        when(featureFlagService.disabledFeatureKeys(ORG_ID)).thenReturn(Set.of(FeatureFlags.CERTIFICATE_DEPLOYMENT,
                FeatureFlags.CREDENTIALS_MANAGEMENT, FeatureFlags.AUDIT_LOGS));
        lenient().when(permissionRepository.findAllByOrderByCreatedAtDesc()).thenReturn(catalogue);
        lenient().when(permissionRepository.findByNameIn(anyCollection())).thenAnswer(i -> {
            Collection<String> names = i.getArgument(0);
            return catalogue.stream().filter(p -> names.contains(p.getName())).toList();
        });
        lenient().when(grantPolicy.isGrantableBy(any(), any())).thenReturn(true);
        lenient().when(roleRepository.save(any(Role.class))).thenAnswer(i -> i.getArgument(0));
    }

    @Test
    void corePermissionsStayListed_whileTheRestOfTheirResourceIsHidden() {
        assertThat(service.getAllPermissions(ORG_ID)).extracting(PermissionDto::getName)
                .containsExactlyInAnyOrder("certificate:read", "certificate:deploy", "credential:read");
    }

    @Test
    void deployAndCredentialRead_canBeGrantedWithTheirFeaturesOff() {
        Role role = customRole(certRead);
        when(roleRepository.findById(12L)).thenReturn(Optional.of(role));

        service.updateRolePermissions(12L, ORG_ID, UpdateRolePermissionsRequest.builder()
                .permissionNames(Set.of("certificate:read", "certificate:deploy", "credential:read")).build());

        assertThat(role.getPermissions()).extracting(Permission::getName)
                .containsExactlyInAnyOrder("certificate:read", "certificate:deploy", "credential:read");
    }

    @Test
    void credentialCreate_stillCannotBeGrantedWithCredentialsManagementOff() {
        when(roleRepository.findById(12L)).thenReturn(Optional.of(customRole(certRead)));

        assertThatThrownBy(() -> service.updateRolePermissions(12L, ORG_ID, UpdateRolePermissionsRequest.builder()
                .permissionNames(Set.of("credential:read", "credential:create")).build()))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Permissions [credential:create] aren't available. Ask your CertPing administrator.");
    }

    private static Permission permission(long id, String name) {
        int separator = name.indexOf(':');
        return Permission.builder().id(id).name(name).resource(name.substring(0, separator))
                .action(name.substring(separator + 1)).build();
    }

    private static Role customRole(Permission... permissions) {
        return Role.builder().id(12L).name("CUSTOM").organization(ORGANIZATION).isSystemRole(false)
                .permissions(new HashSet<>(Set.of(permissions))).build();
    }
}
