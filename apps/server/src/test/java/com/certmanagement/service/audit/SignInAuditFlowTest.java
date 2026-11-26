// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.controller.AuthController;
import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.ResetPasswordRequest;
import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.messaging.AuthNotificationPublisher;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.AccessToken;
import com.certmanagement.security.EmailTokenService;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import com.certmanagement.security.SignInRefusedException;
import com.certmanagement.service.AccessTokenBlacklistService;
import com.certmanagement.service.AdminUserService;
import com.certmanagement.service.LoginAttemptService;
import com.certmanagement.service.PasswordPolicy;
import com.certmanagement.service.PasswordResetService;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.SsoAttributeExtractor;
import com.certmanagement.service.SsoAuthenticationService;
import com.certmanagement.service.UnifiedAuthService;
import com.certmanagement.service.UserProvisioningService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every sign-in flow through its real service and the real {@link AuthAuditRecorder}, down to the rows it
 * hands the {@link AuditRecorder}: one per attempt, in the right trail, with the right actor and reason,
 * and never the identifier someone typed.
 */
class SignInAuditFlowTest {

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final AuthAuditRecorder authAudit = new AuthAuditRecorder(recorder, Clock.systemUTC());
    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final LoginAttemptService loginAttempts = mock(LoginAttemptService.class);

    @BeforeEach
    void fromABrowser() {
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken(any(User.class), any())).thenReturn("refresh");
    }

    @AfterEach
    void clear() {
        RequestContextInterceptor.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private static Organization acme() {
        return Organization.builder().id(42L).name("Acme").domain("acme.test").orgType("B2B").build();
    }

    private static User alice() {
        return User.builder().id(7).username("alice").email("alice@acme.test").passwordHash("hash").active(true)
                .authMethod(User.AuthMethod.LOCAL).organization(acme()).roles(new HashSet<>()).build();
    }

    private AuditEventRow queued() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordAsync(row.capture());
        return row.getValue();
    }

    private AuditEventRow failed() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordFailure(row.capture());
        return row.getValue();
    }

    private AuditEventRow recorded() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).record(row.capture());
        return row.getValue();
    }

    private static void assertCustomerFailure(AuditEventRow row, String code) {
        assertThat(row.event()).isEqualTo("auth.sign_in_failed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(row.errorCode()).isEqualTo(code);
    }

    private static void assertAnonymousFailure(AuditEventRow row, String code) {
        assertThat(row.event()).isEqualTo("auth.sign_in_failed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.actorType()).isEqualTo(AuditActorType.ANONYMOUS);
        assertThat(row.actorUserId()).isNull();
        assertThat(row.errorCode()).isEqualTo(code);
    }

    @Nested
    class Password {

        private final AdminUserService users = new AdminUserService(userRepository, mock(OrganizationRepository.class),
                mock(RoleRepository.class), passwordEncoder, jwtTokenProvider, refreshTokenService,
                mock(PermissionGrantPolicy.class), authAudit, loginAttempts,
                mock(PlatformTransactionManager.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), org.mockito.Mockito.mock(com.certmanagement.service.PasswordPolicy.class));
        private final UnifiedAuthService unified = new UnifiedAuthService(userRepository, users, authAudit);

        private void login(String username, String password) {
            users.authenticate(LocalLoginRequest.builder().username(username).password(password).build());
        }

        @Test
        void aSignInIsTheAccountsRow() {
            User alice = alice();
            when(userRepository.findByEmail("alice@acme.test")).thenReturn(Optional.of(alice));
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
            when(userRepository.findById(7)).thenReturn(Optional.of(alice));
            when(passwordEncoder.matches("right", "hash")).thenReturn(true);

            unified.login(UnifiedLoginRequest.builder().identifier("alice@acme.test").password("right").build());

            AuditEventRow row = queued();
            assertThat(row.event()).isEqualTo("auth.signed_in");
            assertThat(row.summary()).isEqualTo("Signed in with a password");
            assertThat(row.actorUserId()).isEqualTo(7);
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.ipAddress()).isEqualTo("203.0.113.9");
            verify(recorder, never()).recordFailure(any());
        }

        @Test
        void anUnknownIdentifierIsAnAnonymousInternalRowThatNeverHoldsTheIdentifier() {
            String typed = "mallory.typo@victim-corp.example";
            when(userRepository.findByEmail(typed)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> unified.login(UnifiedLoginRequest.builder().identifier(typed).password("pw")
                    .build())).isInstanceOf(UnauthorizedException.class).hasMessage("Invalid username or password");

            AuditEventRow row = failed();
            assertAnonymousFailure(row, "INVALID_CREDENTIALS");
            assertThat(row.organizationId()).isNull();
            assertThat(row.toString()).doesNotContain("mallory").doesNotContain("victim-corp");
        }

        @Test
        void anUnknownUsernameOnTheAdminLoginIsAnonymousToo() {
            when(userRepository.findByUsername("ghost-admin")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> login("ghost-admin", "pw")).isInstanceOf(UnauthorizedException.class);

            AuditEventRow row = failed();
            assertAnonymousFailure(row, "INVALID_CREDENTIALS");
            assertThat(row.toString()).doesNotContain("ghost-admin");
        }

        @Test
        void aWrongPasswordIsInvalidCredentialsInTheAccountsTrail() {
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice()));

            assertThatThrownBy(() -> login("alice", "wrong")).isInstanceOf(UnauthorizedException.class)
                    .hasMessage("Invalid username or password");

            assertCustomerFailure(failed(), "INVALID_CREDENTIALS");
            verify(recorder, never()).recordAsync(any());
            verify(loginAttempts).recordFailure(7);
        }

        @Test
        void theWrongPasswordThatStartsALockIsAnAccountLockedRowWrittenByCertPing() {
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice()));
            when(loginAttempts.recordFailure(7)).thenReturn(Optional.of(new LoginAttemptService.FailedLogin(5,
                    OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(15), true)));

            assertThatThrownBy(() -> login("alice", "wrong")).hasMessage("Invalid username or password");

            assertCustomerFailure(failed(), "INVALID_CREDENTIALS");
            AuditEventRow locked = queued();
            assertThat(locked.event()).isEqualTo("auth.account_locked");
            assertThat(locked.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
            assertThat(locked.organizationId()).isEqualTo(42L);
            assertThat(locked.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(locked.resourceType()).isEqualTo("USER");
            assertThat(locked.resourceId()).isEqualTo(7L);
            assertThat(locked.resourceName()).isNull();
            assertThat(locked.summary()).isEqualTo("a member's account was locked after 5 failed sign-ins");
            assertThat(locked.details().attributes()).containsEntry("attempts", "5");
        }

        @Test
        void aStaffLockoutIsAnInternalAccountLockedRowWrittenByCertPing() {
            User admin = User.builder().id(1).username("root").passwordHash("hash").active(true)
                    .roles(new HashSet<>(Set.of(Role.builder().name(Permissions.ROLE_SUPER_ADMIN).build()))).build();
            when(userRepository.findByUsername("root")).thenReturn(Optional.of(admin));
            when(loginAttempts.recordFailure(1)).thenReturn(Optional.of(new LoginAttemptService.FailedLogin(5,
                    OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(15), true)));

            assertThatThrownBy(() -> login("root", "wrong")).hasMessage("Invalid username or password");

            // Staff have no customer trail: the row is internal, a durable record for support.
            AuditEventRow locked = queued();
            assertThat(locked.event()).isEqualTo("auth.account_locked");
            assertThat(locked.visibility()).isEqualTo(AuditVisibility.INTERNAL);
            assertThat(locked.organizationId()).isNull();
            assertThat(locked.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(locked.resourceType()).isEqualTo("USER");
            assertThat(locked.resourceId()).isEqualTo(1L);
            assertThat(locked.resourceRef()).isEqualTo("1");
            assertThat(locked.details().attributes()).containsEntry("attempts", "5");
        }

        @Test
        void aWrongPasswordWhileTheLockRunsStartsNoSecondLock() {
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice()));
            when(loginAttempts.recordFailure(7)).thenReturn(Optional.of(new LoginAttemptService.FailedLogin(6,
                    OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(15), false)));

            assertThatThrownBy(() -> login("alice", "wrong")).hasMessage("Invalid username or password");

            assertCustomerFailure(failed(), "INVALID_CREDENTIALS");
            verify(recorder, never()).recordAsync(any());
        }

        @Test
        void anUnknownAccountStillPaysForAPasswordCheck() {
            when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());
            when(userRepository.findByEmail("ghost@acme.test")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> login("ghost", "pw-1")).hasMessage("Invalid username or password");
            assertThatThrownBy(() -> unified.login(UnifiedLoginRequest.builder().identifier("ghost@acme.test")
                    .password("pw-2").build())).hasMessage("Invalid username or password");

            verify(passwordEncoder).matches(eq("pw-1"), any());
            verify(passwordEncoder).matches(eq("pw-2"), any());
            verify(loginAttempts, never()).recordFailure(any());
        }

        @Test
        void anAccountWithoutAPasswordIsInvalidCredentials() {
            User alice = alice();
            alice.setPasswordHash(null);
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

            assertThatThrownBy(() -> login("alice", "pw")).isInstanceOf(UnauthorizedException.class);

            assertCustomerFailure(failed(), "INVALID_CREDENTIALS");
        }

        @Test
        void aLockedAccountIsAccountLocked() {
            User alice = alice();
            alice.setLockedUntil(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(10));
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

            // Only a caller who knows the password learns the account is locked; the audit row says so either way.
            when(passwordEncoder.matches("right", "hash")).thenReturn(true);
            assertThatThrownBy(() -> login("alice", "right")).hasMessage("Account is locked. Try again later.");

            assertCustomerFailure(failed(), "ACCOUNT_LOCKED");
            // A locked attempt is not counted again.
            verify(loginAttempts, never()).recordFailure(any());
        }

        @Test
        void aLockedOrDisabledAccountWithAWrongPasswordGetsTheWrongPasswordAnswer() {
            User alice = alice();
            alice.setLockedUntil(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(10));
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

            assertThatThrownBy(() -> login("alice", "guess")).hasMessage("Invalid username or password");

            assertCustomerFailure(failed(), "ACCOUNT_LOCKED");
            verify(loginAttempts, never()).recordFailure(any());
        }

        @Test
        void aDisabledAccountIsAccountDisabled() {
            User alice = alice();
            alice.setActive(false);
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

            when(passwordEncoder.matches("right", "hash")).thenReturn(true);
            assertThatThrownBy(() -> login("alice", "right")).hasMessage("Account is disabled");

            assertCustomerFailure(failed(), "ACCOUNT_DISABLED");
        }

        @Test
        void aSuspendedOrganizationIsOrganizationSuspended() {
            User alice = alice();
            alice.getOrganization().setActive(false);
            when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

            when(passwordEncoder.matches("right", "hash")).thenReturn(true);
            assertThatThrownBy(() -> login("alice", "right")).hasMessage("Organization is suspended or inactive");

            assertCustomerFailure(failed(), "ORGANIZATION_SUSPENDED");
        }

        @Test
        void aStaffSignInAndItsRefusalsAreInternalStaffRows() {
            User admin = User.builder().id(1).username("root").passwordHash("hash").active(true)
                    .roles(new HashSet<>(Set.of(Role.builder().name(Permissions.ROLE_SUPER_ADMIN).build()))).build();
            when(userRepository.findByUsername("root")).thenReturn(Optional.of(admin));
            when(userRepository.findById(1)).thenReturn(Optional.of(admin));

            assertThatThrownBy(() -> login("root", "wrong")).isInstanceOf(UnauthorizedException.class);
            when(passwordEncoder.matches("right", "hash")).thenReturn(true);
            login("root", "right");

            AuditEventRow refused = failed();
            AuditEventRow signedIn = queued();
            assertThat(List.of(refused, signedIn)).allSatisfy(row -> {
                assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
                assertThat(row.actorStaff()).isTrue();
                assertThat(row.actorUserId()).isEqualTo(1);
                assertThat(row.organizationId()).isNull();
            });
        }

        @Test
        void aPasswordChangeIsWrittenAndAWrongCurrentPasswordIsRefused() {
            User alice = alice();
            when(userRepository.findById(7)).thenReturn(Optional.of(alice));
            when(passwordEncoder.matches("current", "hash")).thenReturn(true);
            when(passwordEncoder.encode(anyString())).thenReturn("new-hash");

            assertThatThrownBy(() -> users.changePassword(7, ChangePasswordRequest.builder().currentPassword("guess")
                    .newPassword("a-long-new-password").confirmPassword("a-long-new-password").build()))
                    .isInstanceOf(BadRequestException.class);
            AuditEventRow refused = failed();
            assertThat(refused.event()).isEqualTo("auth.password_changed");
            assertThat(refused.errorCode()).isEqualTo("INVALID_CREDENTIALS");

            users.changePassword(7, ChangePasswordRequest.builder().currentPassword("current")
                    .newPassword("a-long-new-password").confirmPassword("a-long-new-password").build());
            AuditEventRow changed = recorded();
            assertThat(changed.event()).isEqualTo("auth.password_changed");
            assertThat(changed.outcome()).isEqualTo(AuditOutcome.SUCCESS);
            assertThat(changed.actorUserId()).isEqualTo(7);
        }
    }

    @Nested
    class SingleSignOn {

        private final SsoAttributeExtractor extractor = mock(SsoAttributeExtractor.class);
        private final UserProvisioningService provisioning = mock(UserProvisioningService.class);
        private final PlatformOidcRegistration platform = mock(PlatformOidcRegistration.class);
        private final SsoAuthenticationService sso = new SsoAuthenticationService(extractor, provisioning,
                jwtTokenProvider, platform, refreshTokenService, authAudit);
        private final OidcUser oidcUser = mock(OidcUser.class);
        private final OAuth2AuthenticationToken token = mock(OAuth2AuthenticationToken.class);

        @BeforeEach
        void anOidcToken() {
            when(token.getPrincipal()).thenReturn(oidcUser);
        }

        private void idToken(String email) {
            when(platform.owns("org-42-oidc")).thenReturn(true);
            when(platform.ssoConfig()).thenReturn(Optional.of(SsoConfig.builder().organization(acme())
                    .registrationId("org-42-oidc").build()));
            when(extractor.extractFromOidc(eq(oidcUser), any(), any())).thenReturn(SsoUserInfo.builder().email(email)
                    .idpUserId("idp-1").authMethod("OIDC").build());
        }

        @Test
        void aSignInIsOneSignedInRow() {
            idToken("alice@acme.test");
            when(provisioning.findOrProvisionUser(any(), any(), any())).thenReturn(alice());

            sso.processOidcAuthentication(token, "org-42-oidc");

            AuditEventRow row = queued();
            assertThat(row.event()).isEqualTo("auth.signed_in");
            assertThat(row.summary()).isEqualTo("Signed in with single sign-on");
            assertThat(row.actorUserId()).isEqualTo(7);
            assertThat(row.authMethod()).isEqualTo("SSO");
        }

        @Test
        void anUnknownRegistrationIsMisconfiguredAndInternal() {
            assertThatThrownBy(() -> sso.processOidcAuthentication(token, "org-9-nope-oidc"))
                    .isInstanceOf(UnauthorizedException.class).hasMessage("SSO not configured");

            AuditEventRow row = failed();
            assertAnonymousFailure(row, "SSO_MISCONFIGURED");
            assertThat(row.organizationId()).isNull();
            assertThat(row.toString()).doesNotContain("org-9-nope-oidc");
        }

        @Test
        void aTokenWithoutAnEmailIsRejected() {
            idToken(" ");

            assertThatThrownBy(() -> sso.processOidcAuthentication(token, "org-42-oidc"))
                    .isInstanceOf(UnauthorizedException.class);

            AuditEventRow row = internalFailure();
            assertAnonymousFailure(row, "SSO_REJECTED");
            assertThat(row.organizationId()).isEqualTo(42L);
            assertOrganizationTrailFailure(organizationFailure(), "SSO_REJECTED");
        }

        @Test
        void aRefusedProvisioningIsRejected() {
            idToken("newcomer@acme.test");
            when(provisioning.findOrProvisionUser(any(), any(), any()))
                    .thenThrow(new ForbiddenException("Refused"));

            assertThatThrownBy(() -> sso.processOidcAuthentication(token, "org-42-oidc"))
                    .isInstanceOf(ForbiddenException.class);

            AuditEventRow row = internalFailure();
            assertAnonymousFailure(row, "SSO_REJECTED");
            assertThat(row.toString()).doesNotContain("newcomer");
            assertThat(organizationFailure().toString()).doesNotContain("newcomer");
        }

        @Test
        void aPersonWithNoMemberAccountIsNotProvisionedInTheOrganizationsTrail() {
            idToken("newcomer@acme.test");
            when(provisioning.findOrProvisionUser(any(), any(), any())).thenThrow(
                    new com.certmanagement.exception.SsoMemberNotProvisionedException(
                            "User not found and auto-provisioning is disabled"));

            assertThatThrownBy(() -> sso.processOidcAuthentication(token, "org-42-oidc"))
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("User not found and auto-provisioning is disabled");

            assertAnonymousFailure(internalFailure(), "SSO_MEMBER_NOT_PROVISIONED");
            AuditEventRow row = organizationFailure();
            assertOrganizationTrailFailure(row, "SSO_MEMBER_NOT_PROVISIONED");
            assertThat(row.toString()).doesNotContain("newcomer");
        }

        private List<AuditEventRow> failures() {
            ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
            verify(recorder, org.mockito.Mockito.atLeastOnce()).recordFailure(rows.capture());
            return rows.getAllValues();
        }

        private AuditEventRow internalFailure() {
            return failures().stream().filter(row -> row.visibility() == AuditVisibility.INTERNAL).findFirst()
                    .orElseThrow();
        }

        private AuditEventRow organizationFailure() {
            List<AuditEventRow> customer = failures().stream()
                    .filter(row -> row.visibility() == AuditVisibility.CUSTOMER).toList();
            assertThat(customer).hasSize(1);
            return customer.get(0);
        }

        /** "Someone", in the organization's trail, with the reason and method only: no client, no account. */
        private void assertOrganizationTrailFailure(AuditEventRow row, String code) {
            assertThat(row.event()).isEqualTo("auth.sign_in_failed");
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.actorType()).isEqualTo(AuditActorType.ANONYMOUS);
            assertThat(row.actorUserId()).isNull();
            assertThat(row.actorLabel()).isEqualTo("Someone");
            assertThat(row.errorCode()).isEqualTo(code);
            assertThat(row.ipAddress()).isNull();
            assertThat(row.userAgent()).isNull();
            assertThat(row.details().attributes()).containsOnlyKeys("method", "registrationId")
                    .containsEntry("method", "OIDC").containsEntry("registrationId", "org-42-oidc");
            assertThat(row.summary()).isEqualTo("Could not sign in with single sign-on");
        }

        @Test
        void aDisabledMemberIsAccountDisabledInTheirTrail() {
            idToken("alice@acme.test");
            User alice = alice();
            alice.setActive(false);
            when(provisioning.findOrProvisionUser(any(), any(), any())).thenReturn(alice);

            assertThatThrownBy(() -> sso.processOidcAuthentication(token, "org-42-oidc"))
                    .isInstanceOf(SignInRefusedException.class).hasMessage("Account is disabled");

            AuditEventRow row = failed();
            assertCustomerFailure(row, "ACCOUNT_DISABLED");
            assertThat(row.summary()).isEqualTo("Could not sign in with single sign-on");
            verify(recorder, never()).recordAsync(any());
        }
    }


    @Nested
    class SignOutAndReset {

        @Test
        void signingOutIsTheTokensAccountsRow() {
            AccessTokenBlacklistService blacklist = mock(AccessTokenBlacklistService.class);
            AuthController controller = new AuthController(jwtTokenProvider, userRepository, refreshTokenService,
                    blacklist, mock(UnifiedAuthService.class), authAudit);
            AccessToken token = new AccessToken("jti", "alice@acme.test", 7, 42L, List.of("ORGANIZATION_ADMIN"),
                    List.of(), "SSO", Instant.now().plusSeconds(600));
            when(jwtTokenProvider.parseAccessToken("tok")).thenReturn(Optional.of(token));
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer tok");

            controller.logout(request, null);

            AuditEventRow row = queued();
            assertThat(row.event()).isEqualTo("auth.signed_out");
            assertThat(row.actorUserId()).isEqualTo(7);
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.authMethod()).isEqualTo("SSO");
        }

        @Test
        void aLogoutNamingNoOneWritesNothing() {
            AuthController controller = new AuthController(jwtTokenProvider, userRepository, refreshTokenService,
                    mock(AccessTokenBlacklistService.class), mock(UnifiedAuthService.class), authAudit);

            controller.logout(new MockHttpServletRequest(), Map.of("refreshToken", "garbage"));

            verify(recorder, never()).recordAsync(any());
        }

        @Test
        void aResetEmailSentAndAResetCompletedAreTheAccountsRows() throws Exception {
            EmailTokenService tokens = mock(EmailTokenService.class);
            AuthNotificationPublisher publisher = mock(AuthNotificationPublisher.class);
            PasswordResetService reset = new PasswordResetService(userRepository, tokens, passwordEncoder,
                    new PasswordPolicy(), refreshTokenService, authAudit);
            ReflectionTestUtils.setField(reset, "authNotificationPublisher", publisher);
            ReflectionTestUtils.setField(reset, "frontendBaseUrl", "https://app.test");
            when(userRepository.findByEmail("alice@acme.test")).thenReturn(Optional.of(alice()));
            when(tokens.issuePasswordResetToken("alice@acme.test", "hash")).thenReturn("reset-token");
            when(tokens.parsePasswordResetToken("reset-token"))
                    .thenReturn(new EmailTokenService.ParsedEmailToken("alice@acme.test", "jti", EmailTokenService.passwordFingerprint("hash")));
            when(passwordEncoder.encode(anyString())).thenReturn("new-hash");

            reset.forgotPassword("alice@acme.test", "req-1");
            reset.forgotPassword("ghost@nowhere.test", "req-2");
            reset.resetPassword("reset-token", ResetPasswordRequest.builder().newPassword("Zx9!kq-Long-Passphrase")
                    .confirmPassword("Zx9!kq-Long-Passphrase").build(), "req-3");

            AuditEventRow requested = queued();
            assertThat(requested.event()).isEqualTo("auth.password_reset_requested");
            assertThat(requested.actorUserId()).isEqualTo(7);
            assertThat(requested.organizationId()).isEqualTo(42L);
            AuditEventRow completed = recorded();
            assertThat(completed.event()).isEqualTo("auth.password_reset_completed");
            assertThat(completed.actorUserId()).isEqualTo(7);
        }

        @Test
        void aResetRequestWhoseEmailCouldNotBeSentWritesNothing() {
            EmailTokenService tokens = mock(EmailTokenService.class);
            AuthNotificationPublisher publisher = mock(AuthNotificationPublisher.class);
            PasswordResetService reset = new PasswordResetService(userRepository, tokens, passwordEncoder,
                    new PasswordPolicy(), refreshTokenService, authAudit);
            ReflectionTestUtils.setField(reset, "authNotificationPublisher", publisher);
            when(userRepository.findByEmail("alice@acme.test")).thenReturn(Optional.of(alice()));
            when(tokens.issuePasswordResetToken(any(), any())).thenThrow(new IllegalStateException("signing key missing"));

            reset.forgotPassword("alice@acme.test", "req-1");

            verify(recorder, never()).recordAsync(any());
        }
    }
}
