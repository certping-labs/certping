// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.Set;

import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Additional unit tests for {@link AdminUserService} covering branches not exercised by
 * {@code AdminUserServiceTest}: {@code isSystemInitialized}, {@code createUser} duplicate paths,
 * {@code ensureBootstrapSuperAdmin} guards, the full {@code changePassword} rule set, and
 * {@code authenticate} failure branches.
 */
@ExtendWith(MockitoExtension.class)
class AdminUserServiceMoreTest {

    @Mock private UserRepository userRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private LoginAttemptService loginAttemptService;
    @Mock private PlatformTransactionManager transactionManager;

    @Mock private AuthAuditRecorder authAuditRecorder;
    @Mock private com.certmanagement.service.audit.AccessAuditRecorder accessAuditRecorder;
    @Mock private PasswordPolicy passwordPolicy;
    @InjectMocks private AdminUserService service;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminUsername", "root");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminEmail", "root@example.com");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminPassword", "SuperSecret123!");
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminDisplayName", "Root Admin");
    }

    private Role role(String name) {
        Role r = new Role();
        r.setName(name);
        return r;
    }

    @Test
    void isSystemInitializedReflectsUserCount() {
        when(userRepository.count()).thenReturn(2L);
        assertThat(service.isSystemInitialized()).isTrue();
        when(userRepository.count()).thenReturn(0L);
        assertThat(service.isSystemInitialized()).isFalse();
    }

    @Test
    void createUserThrowsDuplicateWhenEmailExists() {
        when(userRepository.findByEmail("dup@x.test")).thenReturn(Optional.of(new User()));
        assertThatThrownBy(() -> service.createUser("bob", "pw", "dup@x.test", "Bob", null, Set.of()))
                .isInstanceOf(DuplicateResourceException.class);
    }

    @Test
    void createUserGeneratesUsernameFromEmailAndDefaultsDisplayName() {
        when(userRepository.findByEmail("alice@acme.test")).thenReturn(Optional.empty());
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(passwordEncoder.encode("pw")).thenReturn("hash");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(1);
            return u;
        });

        User created = service.createUser(null, "pw", "alice@acme.test", null, null, Set.of());

        assertThat(created.getUsername()).isEqualTo("alice");
        assertThat(created.getDisplayName()).isEqualTo("alice");
        assertThat(created.getPasswordHash()).isEqualTo("hash");
    }

    @Test
    void createUserThrowsWhenExplicitUsernameTaken() {
        // resolveUsername runs before the email duplicate check, so existsByUsername throws first.
        when(userRepository.existsByUsername("taken")).thenReturn(true);
        assertThatThrownBy(() -> service.createUser("taken", "pw", "x@y.test", "X", null, Set.of()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Username already exists");
    }

    @Test
    void withoutBootstrapConfigNothingIsCreatedAndSetupStaysOpen() {
        ReflectionTestUtils.setField(service, "bootstrapSuperAdminPassword", "");
        when(userRepository.count()).thenReturn(0L);
        service.ensureBootstrapSuperAdmin();
        verify(userRepository, never()).save(any());
        assertThat(service.isSetupRequired()).isTrue();
    }

    @Test
    void setupIsNoLongerRequiredOnceAnyUserExists() {
        when(userRepository.count()).thenReturn(1L);
        assertThat(service.isSetupRequired()).isFalse();
    }

    @Test
    void firstRunSetupCreatesAnActiveSuperAdminWithAValidatedPassword() {
        when(transactionManager.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        when(userRepository.count()).thenReturn(0L);
        Role superAdmin = Role.builder().name(Permissions.ROLE_SUPER_ADMIN).build();
        when(roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN)).thenReturn(Optional.of(superAdmin));
        when(passwordEncoder.encode("Correct-Horse-Battery-9")).thenReturn("hash");
        when(userRepository.save(any())).thenAnswer(inv -> { User u = inv.getArgument(0); u.setId(1); return u; });

        User created = service.createFirstSuperAdmin(com.certmanagement.dto.auth.SetupRequest.builder()
                .username("owner").email("Owner@Example.com").password("Correct-Horse-Battery-9").build());

        // Concurrent setups serialize on the lock before either looks for an existing user.
        org.mockito.InOrder order = inOrder(userRepository);
        order.verify(userRepository).lockForFirstRunSetup(AdminUserService.FIRST_RUN_SETUP_LOCK_KEY);
        order.verify(userRepository).count();

        verify(passwordPolicy).validate("Correct-Horse-Battery-9", "owner", "Owner@Example.com");
        assertThat(created.getEmail()).isEqualTo("owner@example.com");
        assertThat(created.getActive()).isTrue();
        assertThat(created.getMustChangePassword()).isFalse();
        assertThat(created.getRoles()).containsExactly(superAdmin);
        assertThat(created.getAuthMethod()).isEqualTo(User.AuthMethod.LOCAL);
    }

    @Test
    void firstRunSetupIsRefusedOnceAUserExists() {
        when(transactionManager.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        when(userRepository.count()).thenReturn(1L);
        assertThatThrownBy(() -> service.createFirstSuperAdmin(com.certmanagement.dto.auth.SetupRequest.builder()
                .username("second").email("second@example.com").password("Correct-Horse-Battery-9").build()))
                .isInstanceOf(com.certmanagement.exception.ConflictException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void ensureBootstrapSuperAdminSkipsWhenAlreadyPresent() {
        when(userRepository.findByUsername("root")).thenReturn(Optional.of(new User()));
        service.ensureBootstrapSuperAdmin();
        verify(userRepository, never()).save(any());
    }

    @Test
    void ensureBootstrapSuperAdminThrowsWhenRoleSeedMissing() {
        when(userRepository.findByUsername("root")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("root@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN))
                .thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.ensureBootstrapSuperAdmin())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("role not found");
    }

    @Test
    void changePasswordThrowsWhenUserNotFound() {
        when(userRepository.findById(5)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.changePassword(5, ChangePasswordRequest.builder().build()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void changePasswordThrowsWhenNoPasswordSet() {
        User u = User.builder().build();
        u.setPasswordHash(null);
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        assertThatThrownBy(() -> service.changePassword(5, ChangePasswordRequest.builder().build()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no password set");
    }

    @Test
    void changePasswordThrowsWhenCurrentIncorrect() {
        User u = User.builder().id(5).passwordHash("hash").build();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);
        ChangePasswordRequest req = ChangePasswordRequest.builder().currentPassword("wrong").build();
        assertThatThrownBy(() -> service.changePassword(5, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Current password is incorrect");
        // A wrong current password is a guess like a wrong sign-in: it counts toward the lockout.
        verify(loginAttemptService).recordFailure(5);
        verify(userRepository, never()).save(any());
    }

    @Test
    void changePasswordIsRefusedWhileTheAccountIsLocked() {
        User u = spy(User.builder().id(5).passwordHash("hash").build());
        doReturn(true).when(u).isLocked();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        ChangePasswordRequest req = ChangePasswordRequest.builder().currentPassword("guess").build();
        assertThatThrownBy(() -> service.changePassword(5, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("locked");
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void changePasswordEndsEveryOtherSessionAndKeepsTheCallers() {
        SessionRevocationService revocation = mock(SessionRevocationService.class);
        service.setSessionRevocationService(revocation);
        User u = User.builder().id(5).passwordHash("hash").build();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("cur", "hash")).thenReturn(true);
        when(passwordEncoder.encode("BrandNewPass123")).thenReturn("newhash");
        com.certmanagement.security.AccessToken current = new com.certmanagement.security.AccessToken("jti-1",
                "a@b.c", 5, null, java.util.List.of(), java.util.List.of(), "LOCAL",
                java.time.Instant.now().plusSeconds(600));

        service.changePassword(5, ChangePasswordRequest.builder().currentPassword("cur")
                .newPassword("BrandNewPass123").confirmPassword("BrandNewPass123").build(), current);

        verify(revocation).endAllSessions(5, current);
    }

    @Test
    void changePasswordThrowsWhenConfirmationMismatch() {
        User u = User.builder().passwordHash("hash").build();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("cur", "hash")).thenReturn(true);
        ChangePasswordRequest req = ChangePasswordRequest.builder()
                .currentPassword("cur").newPassword("LongEnoughPass1").confirmPassword("different").build();
        assertThatThrownBy(() -> service.changePassword(5, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("do not match");
    }

    @Test
    void changePasswordAppliesThePasswordPolicy() {
        User u = User.builder().username("bob").email("bob@x.test").passwordHash("hash").build();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("cur", "hash")).thenReturn(true);
        doThrow(new BadRequestException("Password must be at least 12 characters"))
                .when(passwordPolicy).validate("short", "bob", "bob@x.test");
        ChangePasswordRequest req = ChangePasswordRequest.builder()
                .currentPassword("cur").newPassword("short").confirmPassword("short").build();
        assertThatThrownBy(() -> service.changePassword(5, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("at least 12 characters");
        verify(userRepository, never()).save(any());
    }

    @Test
    void changePasswordSucceedsAndClearsMustChangeFlag() {
        User u = User.builder().passwordHash("hash").mustChangePassword(true).build();
        when(userRepository.findById(5)).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("cur", "hash")).thenReturn(true);
        when(passwordEncoder.encode("BrandNewPass123")).thenReturn("newhash");

        ChangePasswordRequest req = ChangePasswordRequest.builder()
                .currentPassword("cur").newPassword("BrandNewPass123").confirmPassword("BrandNewPass123").build();
        service.changePassword(5, req);

        assertThat(u.getPasswordHash()).isEqualTo("newhash");
        assertThat(u.getMustChangePassword()).isFalse();
        verify(userRepository).save(u);
    }

    @Test
    void authenticateThrowsWhenUserNotFound() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());
        LocalLoginRequest req = new LocalLoginRequest();
        req.setUsername("ghost");
        req.setPassword("pw");
        assertThatThrownBy(() -> service.authenticate(req))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Invalid username or password");
    }

    @Test
    void authenticateOnALockedAccountWithTheRightPasswordSaysLocked() {
        User u = spy(User.builder().passwordHash("hash").active(true).build());
        doReturn(true).when(u).isLocked();
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("pw", "hash")).thenReturn(true);
        LocalLoginRequest req = new LocalLoginRequest();
        req.setUsername("bob");
        req.setPassword("pw");
        assertThatThrownBy(() -> service.authenticate(req))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("locked");
        verifyNoInteractions(loginAttemptService);
    }

    @Test
    void authenticateOnALockedOrDisabledAccountWithAWrongPasswordGetsTheGenericAnswer() {
        User locked = spy(User.builder().passwordHash("hash").active(true).build());
        doReturn(true).when(locked).isLocked();
        User disabled = User.builder().passwordHash("hash").active(false).build();
        for (User u : java.util.List.of(locked, disabled)) {
            when(userRepository.findByUsername("bob")).thenReturn(Optional.of(u));
            when(passwordEncoder.matches("guess", "hash")).thenReturn(false);
            LocalLoginRequest req = new LocalLoginRequest();
            req.setUsername("bob");
            req.setPassword("guess");
            assertThatThrownBy(() -> service.authenticate(req))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessage("Invalid username or password");
        }
        verifyNoInteractions(loginAttemptService);
    }

    @Test
    void authenticateRecordsFailedLoginOnBadPassword() {
        User u = User.builder().id(42).passwordHash("hash").active(true).build();
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);
        LocalLoginRequest req = new LocalLoginRequest();
        req.setUsername("bob");
        req.setPassword("wrong");

        assertThatThrownBy(() -> service.authenticate(req))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Invalid username or password");
        // Counted through the separate bean, whose own transaction survives this one's rollback.
        verify(loginAttemptService).recordFailure(42);
        verify(userRepository, never()).save(any());
    }
}
