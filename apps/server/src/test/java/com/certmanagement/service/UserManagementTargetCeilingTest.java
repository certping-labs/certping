// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.user.UserDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every write to an existing user, driven through the real {@link PermissionGrantPolicy}: who may
 * update, email-change, disable, delete, re-role or re-permission whom.
 */
class UserManagementTargetCeilingTest {

    private static final long ORG_ID = 1L;
    private static final long OTHER_ORG_ID = 2L;
    private static final int CALLER_ID = 100;
    private static final int ORG_ADMIN_ID = 200;
    private static final int MEMBER_ID = 300;
    private static final int FOREIGN_ADMIN_ID = 400;

    private static final String HELD = Permissions.CERTIFICATE_READ;
    private static final String NOT_HELD_BY_MANAGER = Permissions.IOT_CERTIFICATE_PROFILE_SYNC;

    private final UserRepository userRepository = mock(UserRepository.class);
    private final RoleRepository roleRepository = mock(RoleRepository.class);
    private final PermissionRepository permissionRepository = mock(PermissionRepository.class);
    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

    private final Organization organization = Organization.builder().id(ORG_ID).orgType("B2B").build();
    private final Organization otherOrganization = Organization.builder().id(OTHER_ORG_ID).orgType("B2B").build();
    private final Map<String, Permission> permissions = Stream.of(
                    HELD, NOT_HELD_BY_MANAGER, Permissions.USERS_MANAGE, Permissions.USERS_DELETE,
                    Permissions.ROLES_ASSIGN, Permissions.PERMISSIONS_ASSIGN, Permissions.FEATURE_FLAGS_ADMINISTER)
            .collect(Collectors.toMap(Function.identity(), UserManagementTargetCeilingTest::permission));

    private final Role orgAdminRole = systemRole(1L, Permissions.ROLE_ORGANIZATION_ADMIN,
            HELD, NOT_HELD_BY_MANAGER, Permissions.USERS_MANAGE, Permissions.USERS_DELETE,
            Permissions.ROLES_ASSIGN, Permissions.PERMISSIONS_ASSIGN);
    private final Role managerRole = customRole(2L, "USER_MANAGER",
            HELD, Permissions.USERS_MANAGE, Permissions.USERS_DELETE,
            Permissions.ROLES_ASSIGN, Permissions.PERMISSIONS_ASSIGN);
    private final Role superAdminRole = systemRole(3L, Permissions.ROLE_SUPER_ADMIN,
            Permissions.FEATURE_FLAGS_ADMINISTER);

    /** Every live user, by id; the admin count reads it. */
    private final Map<Integer, User> users = new LinkedHashMap<>();

    private UserService userService;
    private RoleManagementService roleService;

    @BeforeEach
    void setUp() {
        PermissionGrantPolicy policy = new PermissionGrantPolicy(userRepository, organizationRepository, jwtTokenProvider);
        userService = new UserService(userRepository, mock(UserDomainCertRepository.class), mock(AlertRepository.class),
                refreshTokenService, mock(ApplicationEventPublisher.class), policy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        roleService = new RoleManagementService(roleRepository, permissionRepository, organizationRepository,
                userRepository, policy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));

        add(user(ORG_ADMIN_ID, organization, orgAdminRole));
        add(user(MEMBER_ID, organization));
        add(user(FOREIGN_ADMIN_ID, otherOrganization, orgAdminRole));

        when(userRepository.findById(anyInt())).thenAnswer(i -> Optional.ofNullable(users.get(i.<Integer>getArgument(0))));
        when(userRepository.findByIdAndOrganizationId(anyInt(), anyLong())).thenAnswer(i -> Optional
                .ofNullable(users.get(i.<Integer>getArgument(0)))
                .filter(u -> u.getOrganization() != null
                        && u.getOrganization().getId().equals(i.<Long>getArgument(1))));
        when(userRepository.countActiveWithSystemRoleInOrganizationExcept(anyLong(), anyString(), anyInt()))
                .thenAnswer(i -> users.values().stream()
                        .filter(u -> u.getOrganization() != null
                                && u.getOrganization().getId().equals(i.<Long>getArgument(0)))
                        .filter(u -> !u.getId().equals(i.<Integer>getArgument(2)))
                        .filter(u -> Boolean.TRUE.equals(u.getActive()))
                        .filter(u -> u.getRoleNames().contains(i.<String>getArgument(1)))
                        .count());
        when(organizationRepository.findByIdForUpdate(anyLong())).thenAnswer(i -> Stream.of(organization, otherOrganization)
                .filter(o -> o.getId().equals(i.<Long>getArgument(0)))
                .findFirst());
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
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

    /** Each organization-scoped write to {@code targetId}, as the controllers call them for {@code organizationId}. */
    private Map<String, Executable> writes(int targetId, long organizationId) {
        Map<String, Executable> writes = new LinkedHashMap<>();
        writes.put("update email", () -> userService.updateUserForOrganization(targetId, organizationId, emailChange()));
        writes.put("disable", () -> userService.disableUserForOrganization(targetId, organizationId));
        writes.put("delete", () -> userService.deleteUserForOrganization(targetId, organizationId));
        writes.put("strip roles", () -> roleService.assignRolesToUser(targetId, organizationId, Set.of()));
        writes.put("set permissions", () -> roleService.setUserPermissions(targetId, organizationId, Set.of()));
        writes.put("add permissions", () -> roleService.addUserPermissions(targetId, organizationId, Set.of(HELD)));
        writes.put("remove permissions", () -> roleService.removeUserPermissions(targetId, organizationId, Set.of(HELD)));
        return writes;
    }

    @Nested
    class SuperAdmin {

        @BeforeEach
        void signIn() {
            signInAs(null, superAdminRole);
        }

        @Test
        void mayMakeEveryWriteToAnOrganizationAdmin() {
            writes(ORG_ADMIN_ID, ORG_ID).forEach((name, write) ->
                    assertThatCode(() -> fresh(ORG_ADMIN_ID, write)).as(name).doesNotThrowAnyException());
        }

        @Test
        void mayUseTheUnscopedPaths() {
            assertThatCode(() -> userService.updateUser(FOREIGN_ADMIN_ID, emailChange())).doesNotThrowAnyException();
            assertThatCode(() -> userService.disableUser(FOREIGN_ADMIN_ID)).doesNotThrowAnyException();
            assertThatCode(() -> userService.deleteUser(FOREIGN_ADMIN_ID)).doesNotThrowAnyException();
        }

        @Test
        void mayLowerAnOrganizationsOnlyAdmin() {
            assertThatCode(() -> userService.disableUserForOrganization(ORG_ADMIN_ID, ORG_ID)).doesNotThrowAnyException();
        }

        @Test
        void theTokenRoleAloneDoesNotMakeASuperAdmin() {
            users.get(CALLER_ID).getRoles().clear();

            assertThatThrownBy(() -> userService.updateUser(FOREIGN_ADMIN_ID, emailChange()))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("outside your organization");
            assertThat(users.get(FOREIGN_ADMIN_ID).getEmail()).isEqualTo("user" + FOREIGN_ADMIN_ID + "@example.com");
        }
    }

    @Nested
    class SameOrganizationAdmin {

        @BeforeEach
        void signIn() {
            signInAs(organization, orgAdminRole);
        }

        @Test
        void mayMakeEveryWriteToAnotherOrganizationAdmin() {
            writes(ORG_ADMIN_ID, ORG_ID).forEach((name, write) ->
                    assertThatCode(() -> fresh(ORG_ADMIN_ID, write)).as(name).doesNotThrowAnyException());
        }

        @Test
        void mayMakeEveryWriteToAMember() {
            writes(MEMBER_ID, ORG_ID).forEach((name, write) ->
                    assertThatCode(() -> fresh(MEMBER_ID, write)).as(name).doesNotThrowAnyException());
        }

        @Test
        void mayNotManageAnAdminWhoHoldsMore() {
            users.get(ORG_ADMIN_ID).getPermissions().add(permissions.get(Permissions.FEATURE_FLAGS_ADMINISTER));

            assertRefusedEverywhere(ORG_ADMIN_ID, ORG_ID, "holds permissions the caller does not hold");
        }

        @Test
        void mayNotManageAnotherOrganizationsUsers() {
            assertRefusedEverywhere(FOREIGN_ADMIN_ID, OTHER_ORG_ID, "outside your organization");
        }

        @Test
        void aTokenWithoutTheRoleDoesNotMakeAnOrganizationAdmin() {
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                    "caller", "n/a", orgAdminRole.getPermissions().stream()
                    .map(p -> new SimpleGrantedAuthority(p.getName())).toList()));

            assertRefusedEverywhere(ORG_ADMIN_ID, ORG_ID, "Only an organization admin");
        }
    }

    @Nested
    class UsersManageHolder {

        @BeforeEach
        void signIn() {
            signInAs(organization, managerRole);
        }

        @Test
        void mayNotMakeAnyWriteToTheOrganizationAdmin() {
            assertRefusedEverywhere(ORG_ADMIN_ID, ORG_ID, "Only an organization admin can manage an organization admin");
        }

        @Test
        void cannotRedirectTheOrganizationAdminsEmail() {
            assertThatThrownBy(() -> userService.updateUserForOrganization(ORG_ADMIN_ID, ORG_ID, emailChange()))
                    .isInstanceOf(AccessDeniedException.class);

            assertThat(users.get(ORG_ADMIN_ID).getEmail()).isEqualTo("user" + ORG_ADMIN_ID + "@example.com");
        }

        @Test
        void mayMakeEveryWriteToAMemberWithinTheirOwnPermissions() {
            users.get(MEMBER_ID).getPermissions().add(permissions.get(HELD));

            writes(MEMBER_ID, ORG_ID).forEach((name, write) ->
                    assertThatCode(() -> fresh(MEMBER_ID, write)).as(name).doesNotThrowAnyException());
        }

        @Test
        void mayNotManageAMemberWhoHoldsAPermissionTheyLack() {
            users.get(MEMBER_ID).getPermissions().add(permissions.get(NOT_HELD_BY_MANAGER));

            assertRefusedEverywhere(MEMBER_ID, ORG_ID, NOT_HELD_BY_MANAGER);
        }
    }

    @Nested
    class LastOrganizationAdmin {

        @BeforeEach
        void signInAsTheOnlyAdmin() {
            users.remove(ORG_ADMIN_ID);
            signInAs(organization, orgAdminRole);
        }

        @Test
        void cannotLowerThemselves() {
            Map<String, Executable> lowering = new LinkedHashMap<>();
            lowering.put("deactivate", () -> userService.updateUserForOrganization(CALLER_ID, ORG_ID, deactivation()));
            lowering.put("disable", () -> userService.disableUserForOrganization(CALLER_ID, ORG_ID));
            lowering.put("delete", () -> userService.deleteUserForOrganization(CALLER_ID, ORG_ID));
            lowering.put("strip roles", () -> roleService.assignRolesToUser(CALLER_ID, ORG_ID, Set.of()));

            lowering.forEach((name, write) -> assertThatThrownBy(write::execute).as(name)
                    .isInstanceOf(LastOrganizationAdminException.class)
                    .hasMessage("An organization needs at least one active admin"));
            verify(organizationRepository, atLeastOnce()).findByIdForUpdate(ORG_ID);
            verifyNothingWritten();
            assertThat(users.get(CALLER_ID).getActive()).isTrue();
            assertThat(users.get(CALLER_ID).getRoleNames()).contains(Permissions.ROLE_ORGANIZATION_ADMIN);
        }

        @Test
        void aMissingOrganizationRowIsNotFound() {
            when(organizationRepository.findByIdForUpdate(ORG_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.disableUserForOrganization(CALLER_ID, ORG_ID))
                    .isInstanceOf(ResourceNotFoundException.class);
            verifyNothingWritten();
        }

        @Test
        void mayStillEditThemselvesWithoutSteppingDown() {
            assertThatCode(() -> userService.updateUserForOrganization(CALLER_ID, ORG_ID, emailChange()))
                    .doesNotThrowAnyException();
            verify(organizationRepository, never()).findByIdForUpdate(anyLong());
        }

        @Test
        void mayStepDownOnceAnotherActiveAdminExists() {
            User second = user(201, organization, orgAdminRole);
            second.setActive(false);
            add(second);

            assertThatThrownBy(() -> userService.disableUserForOrganization(CALLER_ID, ORG_ID))
                    .isInstanceOf(LastOrganizationAdminException.class);

            second.setActive(true);
            assertThatCode(() -> userService.disableUserForOrganization(CALLER_ID, ORG_ID)).doesNotThrowAnyException();
        }
    }

    private void assertRefusedEverywhere(int targetId, long organizationId, String reason) {
        writes(targetId, organizationId).forEach((name, write) -> assertThatThrownBy(write::execute).as(name)
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining(reason));
        verifyNothingWritten();
    }

    private void verifyNothingWritten() {
        verify(userRepository, never()).save(any(User.class));
        verify(userRepository, never()).softDeleteUserRolesByUserId(anyInt());
        verify(refreshTokenService, never()).revokeAllForUser(anyInt());
    }

    /** Runs {@code write} against a fresh copy of the target, so one write does not change the next one's target. */
    private void fresh(int targetId, Executable write) throws Throwable {
        User original = users.get(targetId);
        users.put(targetId, copy(original));
        try {
            write.execute();
        } finally {
            users.put(targetId, original);
        }
    }

    /** Signs in a caller whose token and database record both carry {@code role}. */
    private void signInAs(Organization callerOrganization, Role role) {
        User caller = user(CALLER_ID, callerOrganization, role);
        add(caller);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
        role.getPermissions().stream().map(p -> new SimpleGrantedAuthority(p.getName())).forEach(authorities::add);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("caller", "n/a", authorities));
        GatewayRequestContext.set(CALLER_ID, callerOrganization == null ? null : String.valueOf(callerOrganization.getId()),
                "req", "caller@example.com");
    }

    private void add(User user) {
        users.put(user.getId(), user);
    }

    private static User user(int id, Organization organization, Role... roles) {
        return User.builder().id(id).email("user" + id + "@example.com").organization(organization).active(true)
                .roles(new HashSet<>(List.of(roles))).permissions(new HashSet<>()).build();
    }

    private static User copy(User user) {
        return User.builder().id(user.getId()).email(user.getEmail()).organization(user.getOrganization())
                .active(user.getActive()).roles(new HashSet<>(user.getRoles()))
                .permissions(new HashSet<>(user.getPermissions())).build();
    }

    private Role systemRole(long id, String name, String... permissionNames) {
        return Role.builder().id(id).name(name).isSystemRole(true).permissions(permissionSet(permissionNames)).build();
    }

    private Role customRole(long id, String name, String... permissionNames) {
        return Role.builder().id(id).name(name).isSystemRole(false).organization(organization)
                .permissions(permissionSet(permissionNames)).build();
    }

    private Set<Permission> permissionSet(String... names) {
        return new HashSet<>(Stream.of(names).map(permissions::get).toList());
    }

    private static UserDto emailChange() {
        return UserDto.builder().email("attacker@evil.test").active(true).build();
    }

    private static UserDto deactivation() {
        return UserDto.builder().email("caller@example.com").active(false).build();
    }

    private static Permission permission(String name) {
        return Permission.builder().id((long) Math.abs(name.hashCode())).name(name)
                .resource(name.split(":")[0]).action(name.split(":")[1]).build();
    }
}
