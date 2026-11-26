// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.CreateUserRequest;
import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every grant path, driven through the real {@link PermissionGrantPolicy}: a platform permission
 * and a permission the caller does not hold are refused, a held one is granted, and no one but a
 * super admin widens their own grants.
 */
class PermissionGrantCeilingTest {

    private static final long ORG_ID = 1L;
    private static final long OTHER_ORG_ID = 2L;
    private static final int CALLER_ID = 100;
    private static final int TARGET_ID = 200;

    private static final String HELD = Permissions.CERTIFICATE_READ;
    private static final String NOT_HELD = Permissions.IOT_CERTIFICATE_PROFILE_SYNC;
    private static final String PLATFORM = Permissions.FEATURE_FLAGS_ADMINISTER;
    private static final String ADMIN_ONLY = Permissions.ORGANIZATION_MANAGE;

    private final UserRepository userRepository = mock(UserRepository.class);
    private final RoleRepository roleRepository = mock(RoleRepository.class);
    private final PermissionRepository permissionRepository = mock(PermissionRepository.class);
    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);

    private final Organization organization = Organization.builder().id(ORG_ID).orgType("B2B").build();
    private final Map<String, Permission> permissions = Stream.of(
                    HELD, NOT_HELD, PLATFORM, ADMIN_ONLY, Permissions.PERMISSIONS_ASSIGN, Permissions.ROLES_ASSIGN,
                    Permissions.ROLES_CREATE, Permissions.USERS_CREATE)
            .collect(Collectors.toMap(Function.identity(), PermissionGrantCeilingTest::permission));

    private RoleManagementService roles;
    private AdminUserService users;
    private User target;

    @BeforeEach
    void setUp() {
        PermissionGrantPolicy policy = new PermissionGrantPolicy(userRepository, organizationRepository, jwtTokenProvider);
        roles = new RoleManagementService(roleRepository, permissionRepository, organizationRepository,
                userRepository, policy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        users = new AdminUserService(userRepository, organizationRepository, roleRepository,
                mock(PasswordEncoder.class), jwtTokenProvider, mock(RefreshTokenService.class), policy, mock(AuthAuditRecorder.class), mock(LoginAttemptService.class),
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));

        target = user(TARGET_ID);
        when(userRepository.findByIdAndOrganizationId(TARGET_ID, ORG_ID)).thenReturn(Optional.of(target));
        when(userRepository.save(any(User.class))).thenAnswer(i -> AdminUserServiceTest.withId(i.getArgument(0)));
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(roleRepository.save(any(Role.class))).thenAnswer(i -> i.getArgument(0));
        when(organizationRepository.findById(ORG_ID)).thenReturn(Optional.of(organization));
        when(permissionRepository.findByNameIn(anyCollection())).thenAnswer(i -> {
            Collection<String> names = i.getArgument(0);
            return names.stream().map(permissions::get).toList();
        });
        when(jwtTokenProvider.effectivePermissions(any(User.class), any()))
                .thenAnswer(i -> ((User) i.getArgument(0)).getEffectivePermissionNames());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    /** Each path, asked to grant one permission (directly, or through a new role holding it). */
    private List<Executable> grantPaths(String permissionName) {
        Role roleWithIt = customRole(50L, ORG_ID, permissionName);
        when(roleRepository.findById(50L)).thenReturn(Optional.of(roleWithIt));
        when(roleRepository.findAllById(Set.of(50L))).thenReturn(List.of(roleWithIt));
        Role editable = customRole(51L, ORG_ID);
        when(roleRepository.findById(51L)).thenReturn(Optional.of(editable));
        return List.of(
                () -> roles.setUserPermissions(TARGET_ID, ORG_ID, Set.of(permissionName)),
                () -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(permissionName)),
                () -> roles.createRole(createRole(permissionName), ORG_ID),
                () -> roles.updateRolePermissions(51L, ORG_ID, updateRole(permissionName)),
                () -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(50L)),
                () -> users.createUserFromRequest(createUser(50L), organization));
    }

    @Nested
    class OrgAdmin {

        @BeforeEach
        void signIn() {
            // Holds the platform permission as org admins once did, in the token and the database.
            signInAs(Permissions.ROLE_ORGANIZATION_ADMIN, HELD, PLATFORM, ADMIN_ONLY, Permissions.PERMISSIONS_ASSIGN,
                    Permissions.ROLES_ASSIGN, Permissions.ROLES_CREATE, Permissions.USERS_CREATE);
        }

        @Test
        void everyPathRefusesAnOrganizationAdminPermissionOutsideTheRole() {
            for (Executable path : grantPaths(ADMIN_ONLY)) {
                assertThatThrownBy(path::execute)
                        .isInstanceOf(AccessDeniedException.class)
                        .hasMessageContaining("only with the ORGANIZATION_ADMIN role")
                        .hasMessageContaining(ADMIN_ONLY);
            }
            verifyNothingSaved();
        }

        @Test
        void promotingAMemberThenSavingTheRolesPermissionsAsDirectGrantsSucceeds() {
            Role organizationAdmin = organizationAdminRole(HELD, ADMIN_ONLY);
            roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId()));

            assertThatCode(() -> roles.setUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD, ADMIN_ONLY)))
                    .doesNotThrowAnyException();
            assertThat(target.getPermissionNames()).containsExactly(HELD);
            assertThat(target.getEffectivePermissionNames()).contains(ADMIN_ONLY);
        }

        @Test
        void editingAnotherOrganizationAdminSavesTheirPermissionsWithoutTheRoleOnlyOnes() {
            target.getRoles().add(organizationAdminRole(HELD, ADMIN_ONLY));
            target.getPermissions().add(permissions.get(ADMIN_ONLY));

            assertThatCode(() -> roles.setUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD, ADMIN_ONLY)))
                    .doesNotThrowAnyException();
            assertThat(target.getPermissionNames()).containsExactly(HELD);

            assertThatCode(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(ADMIN_ONLY)))
                    .doesNotThrowAnyException();
            assertThat(target.getPermissionNames()).containsExactly(HELD);
        }

        @Test
        void losingTheOrganizationAdminRoleTakesTheDirectRoleOnlyGrantWithIt() {
            target.getRoles().add(organizationAdminRole(HELD, ADMIN_ONLY));
            target.getPermissions().add(permissions.get(ADMIN_ONLY));
            target.getPermissions().add(permissions.get(HELD));
            when(organizationRepository.findByIdForUpdate(ORG_ID)).thenReturn(Optional.of(organization));
            when(userRepository.countActiveWithSystemRoleInOrganizationExcept(ORG_ID,
                    Permissions.ROLE_ORGANIZATION_ADMIN, TARGET_ID)).thenReturn(1L);

            roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of());

            assertThat(target.getRoles()).isEmpty();
            assertThat(target.getPermissionNames()).containsExactly(HELD);
        }

        @Test
        void aMemberWhoIsNotAnOrganizationAdminStillCannotBeGivenARoleOnlyPermission() {
            assertThatThrownBy(() -> roles.setUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD, ADMIN_ONLY)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("only with the ORGANIZATION_ADMIN role");
            verifyNothingSaved();
        }

        @Test
        void cannotAssignTheSuperAdminRole() {
            Role superAdmin = Role.builder().id(61L).name(Permissions.ROLE_SUPER_ADMIN).isSystemRole(true)
                    .permissions(new HashSet<>()).build();
            when(roleRepository.findAllById(Set.of(61L))).thenReturn(List.of(superAdmin));

            assertThatThrownBy(() -> users.createUserFromRequest(createUser(61L), organization))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only a super admin can assign the SUPER_ADMIN role");
            verifyNothingSaved();
        }

        @Test
        void theCatalogueLeavesOutTheRoleOnlyPermissions() {
            when(permissionRepository.findAllByOrderByCreatedAtDesc()).thenReturn(List.copyOf(permissions.values()));

            assertThat(roles.getAllPermissions(ORG_ID)).extracting(PermissionDto::getName)
                    .doesNotContain(ADMIN_ONLY, PLATFORM)
                    .contains(HELD);
        }

        @Test
        void stillAssignsTheOrganizationAdminRole() {
            Role organizationAdmin = organizationAdminRole(HELD, ADMIN_ONLY);

            assertThatCode(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId())))
                    .doesNotThrowAnyException();
            assertThatCode(() -> users.createUserFromRequest(createUser(organizationAdmin.getId()), organization))
                    .doesNotThrowAnyException();
            assertThat(target.getRoles()).contains(organizationAdmin);
        }

        @Test
        void everyPathRefusesAPlatformPermission() {
            for (Executable path : grantPaths(PLATFORM)) {
                assertThatThrownBy(path::execute)
                        .isInstanceOf(AccessDeniedException.class)
                        .hasMessageContaining("Only a super admin can grant platform permissions")
                        .hasMessageContaining(PLATFORM);
            }
            verifyNothingSaved();
        }

        @Test
        void everyPathRefusesAPermissionTheCallerDoesNotHold() {
            for (Executable path : grantPaths(NOT_HELD)) {
                assertThatThrownBy(path::execute)
                        .isInstanceOf(AccessDeniedException.class)
                        .hasMessageContaining("does not hold")
                        .hasMessageContaining(NOT_HELD);
            }
            verifyNothingSaved();
        }

        @Test
        void everyPathGrantsAPermissionTheCallerHolds() {
            for (Executable path : grantPaths(HELD)) {
                assertThatCode(path::execute).doesNotThrowAnyException();
            }
        }

        @Test
        void aNewlySeededPermissionIsHeldBeforeTheTokenRefreshes() {
            User caller = userRepository.findById(CALLER_ID).orElseThrow();
            caller.getRoles().iterator().next().getPermissions().add(permissions.get(NOT_HELD));
            Role roleWithIt = customRole(52L, ORG_ID, NOT_HELD);
            when(roleRepository.findById(52L)).thenReturn(Optional.of(roleWithIt));

            assertThatCode(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(52L))).doesNotThrowAnyException();
            assertThatCode(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD)))
                    .doesNotThrowAnyException();
            assertThat(target.getRoles()).contains(roleWithIt);
            assertThat(target.getPermissionNames()).containsExactly(HELD);
        }

        @Test
        void aRevokedPermissionIsNotHeldEvenIfTheTokenHasIt() {
            User caller = userRepository.findById(CALLER_ID).orElseThrow();
            caller.getRoles().iterator().next().getPermissions().removeIf(p -> p.getName().equals(HELD));
            target.getPermissions().add(permissions.get(HELD));

            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(Permissions.ROLES_ASSIGN)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("holds permissions the caller does not hold")
                    .hasMessageContaining(HELD);
            verifyNothingSaved();
        }

        @Test
        void aRemovedOrganizationAdminRoleStillBlocksAdminOnlyGrants() {
            User caller = userRepository.findById(CALLER_ID).orElseThrow();
            Role adminRole = caller.getRoles().iterator().next();
            caller.getRoles().clear();
            caller.getRoles().add(customRole(53L, ORG_ID, adminRole.getPermissions().stream()
                    .map(Permission::getName).toArray(String[]::new)));
            Role organizationAdmin = organizationAdminRole(HELD, ADMIN_ONLY);

            assertThatThrownBy(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId())))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(ADMIN_ONLY)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("only with the ORGANIZATION_ADMIN role");
            target.getRoles().add(organizationAdmin);
            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can manage an organization admin");
            verifyNothingSaved();
        }

        @Test
        void aPermissionTheCallerLostSinceTheTokenWasIssuedIsNotHeld() {
            User caller = userRepository.findById(CALLER_ID).orElseThrow();
            caller.getRoles().iterator().next().getPermissions().removeIf(p -> p.getName().equals(HELD));

            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("does not hold");
        }

        @Test
        void aTargetHoldingMoreThanTheCallerIsOutOfReach() {
            target.getPermissions().add(permissions.get(NOT_HELD));

            assertThatThrownBy(() -> roles.setUserPermissions(TARGET_ID, ORG_ID, Set.of(NOT_HELD, HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("holds permissions the caller does not hold")
                    .hasMessageContaining(NOT_HELD);
            verifyNothingSaved();
        }

        @Test
        void createUserRefusesAnotherOrganizationsCustomRole() {
            Role foreign = customRole(60L, OTHER_ORG_ID, HELD);
            when(roleRepository.findAllById(Set.of(60L))).thenReturn(List.of(foreign));

            assertThatThrownBy(() -> users.createUserFromRequest(createUser(60L), organization))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessageContaining("role IDs are invalid");
        }
    }

    @Nested
    class SelfEscalation {

        private User caller;

        @BeforeEach
        void signIn() {
            caller = signInAs("DELEGATED_ADMIN", HELD, Permissions.PERMISSIONS_ASSIGN, Permissions.ROLES_ASSIGN);
            when(userRepository.findByIdAndOrganizationId(CALLER_ID, ORG_ID)).thenReturn(Optional.of(caller));
        }

        @Test
        void cannotGrantThemselvesADirectPermissionEvenOneTheyHold() {
            assertThatThrownBy(() -> roles.addUserPermissions(CALLER_ID, ORG_ID, Set.of(HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("to yourself");
            assertThatThrownBy(() -> roles.setUserPermissions(CALLER_ID, ORG_ID, Set.of(HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("to yourself");
        }

        @Test
        void cannotAssignThemselvesARoleWithMoreThanTheyHold() {
            Role bigger = customRole(70L, ORG_ID, HELD, NOT_HELD);
            when(roleRepository.findById(70L)).thenReturn(Optional.of(bigger));

            assertThatThrownBy(() -> roles.assignRolesToUser(CALLER_ID, ORG_ID, Set.of(70L)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("to yourself");
            assertThat(caller.getRoles()).doesNotContain(bigger);
        }

        @Test
        void cannotAddPermissionsToARoleTheyHoldEvenOnesTheyHold() {
            Role own = customRole(80L, ORG_ID);
            caller.getRoles().add(own);
            when(roleRepository.findById(80L)).thenReturn(Optional.of(own));

            assertThatThrownBy(() -> roles.updateRolePermissions(80L, ORG_ID, updateRole(HELD)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("a role you hold");
            assertThat(own.getPermissions()).isEmpty();
        }

        @Test
        void mayStillDropTheirOwnDirectPermissions() {
            caller.getPermissions().add(permissions.get(HELD));

            assertThat(roles.removeUserPermissions(CALLER_ID, ORG_ID, Set.of(HELD))).isEmpty();
        }
    }

    @Nested
    class NotAnOrganizationAdmin {

        @Test
        void aDelegateCannotPassOnOrganizationManageEvenWhenTheyHoldIt() {
            signInAs("DELEGATED_ADMIN", HELD, ADMIN_ONLY, Permissions.PERMISSIONS_ASSIGN, Permissions.ROLES_CREATE);

            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(ADMIN_ONLY)))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("only with the ORGANIZATION_ADMIN role");
            assertThatThrownBy(() -> roles.createRole(createRole(ADMIN_ONLY), ORG_ID))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("only with the ORGANIZATION_ADMIN role");
            verifyNothingSaved();
        }

        @Test
        void aDelegateCannotAssignTheOrganizationAdminRole() {
            signInAs("DELEGATED_ADMIN", HELD, Permissions.ROLES_ASSIGN, Permissions.USERS_CREATE);
            Role organizationAdmin = organizationAdminRole(HELD);

            assertThatThrownBy(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId())))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            assertThatThrownBy(() -> users.createUserFromRequest(createUser(organizationAdmin.getId()), organization))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            verifyNothingSaved();
        }

        @Test
        void theDatabaseRoleAloneCannotAssignTheOrganizationAdminRole() {
            signInAs(Permissions.ROLE_ORGANIZATION_ADMIN, HELD, Permissions.ROLES_ASSIGN);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                    "caller", "n/a", List.of(new SimpleGrantedAuthority(HELD),
                    new SimpleGrantedAuthority(Permissions.ROLES_ASSIGN))));
            Role organizationAdmin = organizationAdminRole(HELD);

            assertThatThrownBy(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId())))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            assertThat(target.getRoles()).isEmpty();
        }

        @Test
        void theTokenRoleAloneCannotAssignTheOrganizationAdminRole() {
            User caller = signInAs(Permissions.ROLE_ORGANIZATION_ADMIN, HELD, ADMIN_ONLY, Permissions.ROLES_ASSIGN);
            caller.getRoles().iterator().next().setName("DEMOTED");
            Role organizationAdmin = organizationAdminRole(HELD, ADMIN_ONLY);

            assertThatThrownBy(() -> roles.assignRolesToUser(TARGET_ID, ORG_ID, Set.of(organizationAdmin.getId())))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("Only an organization admin can assign the ORGANIZATION_ADMIN role");
            assertThat(target.getRoles()).isEmpty();
        }
    }

    @Nested
    class SuperAdmin {

        @BeforeEach
        void signIn() {
            signInAs(Permissions.ROLE_SUPER_ADMIN, PLATFORM);
        }

        @Test
        void everyPathGrantsAPlatformPermission() {
            for (Executable path : grantPaths(PLATFORM)) {
                assertThatCode(path::execute).doesNotThrowAnyException();
            }
        }

        @Test
        void theCatalogueOffersTheRoleOnlyPermissions() {
            when(permissionRepository.findAllByOrderByCreatedAtDesc()).thenReturn(List.copyOf(permissions.values()));

            assertThat(roles.getAllPermissions(ORG_ID)).extracting(PermissionDto::getName)
                    .contains(ADMIN_ONLY)
                    .doesNotContain(PLATFORM);
        }

        @Test
        void everyPathGrantsAnOrganizationAdminPermission() {
            for (Executable path : grantPaths(ADMIN_ONLY)) {
                assertThatCode(path::execute).doesNotThrowAnyException();
            }
        }

        @Test
        void theTokenRoleAloneDoesNotMakeASuperAdmin() {
            User caller = userRepository.findById(CALLER_ID).orElseThrow();
            caller.getRoles().clear();

            assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(PLATFORM)))
                    .isInstanceOf(AccessDeniedException.class);
        }
    }

    @Test
    void aCallerWithNoUserIdentityCanGrantNothing() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "service", "n/a", List.of(new SimpleGrantedAuthority(HELD))));

        assertThatThrownBy(() -> roles.addUserPermissions(TARGET_ID, ORG_ID, Set.of(HELD)))
                .isInstanceOf(AccessDeniedException.class);
    }

    /** Signs in a caller whose token and database record both carry {@code roleName} with these permissions. */
    private User signInAs(String roleName, String... permissionNames) {
        Role role = Role.builder().id(900L).name(roleName).isSystemRole(true)
                .permissions(new HashSet<>(Stream.of(permissionNames).map(permissions::get).toList()))
                .build();
        User caller = user(CALLER_ID);
        caller.getRoles().add(role);
        when(userRepository.findById(CALLER_ID)).thenReturn(Optional.of(caller));

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + roleName));
        Stream.of(permissionNames).map(SimpleGrantedAuthority::new).forEach(authorities::add);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("caller", "n/a", authorities));
        GatewayRequestContext.set(CALLER_ID, String.valueOf(ORG_ID), "req", "caller@example.com");
        return caller;
    }

    private void verifyNothingSaved() {
        verify(userRepository, never()).save(any(User.class));
        verify(roleRepository, never()).save(any(Role.class));
    }

    private User user(int id) {
        return User.builder().id(id).organization(organization)
                .roles(new HashSet<>()).permissions(new HashSet<>()).build();
    }

    private Role organizationAdminRole(String... permissionNames) {
        Role role = Role.builder().id(60L).name(Permissions.ROLE_ORGANIZATION_ADMIN).isSystemRole(true)
                .permissions(new HashSet<>(Stream.of(permissionNames).map(permissions::get).toList()))
                .build();
        when(roleRepository.findById(60L)).thenReturn(Optional.of(role));
        when(roleRepository.findAllById(Set.of(60L))).thenReturn(List.of(role));
        return role;
    }

    private Role customRole(long id, long orgId, String... permissionNames) {
        return Role.builder().id(id).name("CUSTOM_" + id).isSystemRole(false)
                .organization(Organization.builder().id(orgId).build())
                .permissions(new HashSet<>(Stream.of(permissionNames).map(permissions::get).toList()))
                .build();
    }

    private static Permission permission(String name) {
        return Permission.builder().id((long) Math.abs(name.hashCode())).name(name)
                .resource(name.split(":")[0]).action(name.split(":")[1]).build();
    }

    private static CreateRoleRequest createRole(String permissionName) {
        return CreateRoleRequest.builder().name("new_role").permissionNames(Set.of(permissionName)).build();
    }

    private static UpdateRolePermissionsRequest updateRole(String permissionName) {
        return updateRole(Set.of(permissionName));
    }

    private static UpdateRolePermissionsRequest updateRole(Set<String> permissionNames) {
        UpdateRolePermissionsRequest request = new UpdateRolePermissionsRequest();
        request.setPermissionNames(permissionNames);
        return request;
    }

    private static CreateUserRequest createUser(long roleId) {
        return CreateUserRequest.builder().email("new@example.com").password("a-long-password-1")
                .roleIds(Set.of(roleId)).build();
    }
}
