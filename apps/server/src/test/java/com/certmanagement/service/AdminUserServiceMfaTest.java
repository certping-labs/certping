// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.SignInFailures;
import com.certmanagement.security.SignInRefusedException;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The second sign-in step: a confirmed factor turns the password check into a challenge. */
@ExtendWith(MockitoExtension.class)
class AdminUserServiceMfaTest {

    @Mock private UserRepository userRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private AuthAuditRecorder authAuditRecorder;
    @Mock private LoginAttemptService loginAttemptService;
    @Mock private PlatformTransactionManager transactionManager;
    @Mock private AccessAuditRecorder accessAudit;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private MfaService mfaService;

    @InjectMocks private AdminUserService service;

    private User user;

    @BeforeEach
    void setUp() {
        service.setMfaService(mfaService);
        user = User.builder().id(7).username("ada").email("ada@example.com").passwordHash("hash").active(true)
                .organization(Organization.builder().id(3L).name("Acme").active(true).isDeleted(false).build())
                .build();
        org.mockito.Mockito.lenient().when(userRepository.findByUsername("ada")).thenReturn(Optional.of(user));
    }

    private static LocalLoginRequest login(String password) {
        return LocalLoginRequest.builder().username("ada").password(password).build();
    }

    @Test
    void rightPasswordWithAFactorReturnsAChallengeAndNoTokens() {
        when(passwordEncoder.matches("pw", "hash")).thenReturn(true);
        when(mfaService.isEnabled(7)).thenReturn(true);
        when(mfaService.challenge(7)).thenReturn("challenge-token");

        LocalLoginResponse response = service.authenticate(login("pw"));

        assertThat(response.getMfaRequired()).isTrue();
        assertThat(response.getMfaToken()).isEqualTo("challenge-token");
        assertThat(response.getToken()).isNull();
        verify(jwtTokenProvider, never()).generateAccessToken(any(), any(), anyString());
        verify(authAuditRecorder, never()).signedIn(any(), any(), any());
    }

    @Test
    void wrongPasswordNeverReachesTheFactor() {
        when(passwordEncoder.matches("nope", "hash")).thenReturn(false);
        assertThatThrownBy(() -> service.authenticate(login("nope"))).isInstanceOf(SignInRefusedException.class);
        verify(mfaService, never()).isEnabled(any());
        verify(mfaService, never()).challenge(any());
    }

    @Test
    void withoutAFactorTheSignInCompletesAsBefore() {
        when(passwordEncoder.matches("pw", "hash")).thenReturn(true);
        when(mfaService.isEnabled(7)).thenReturn(false);
        when(jwtTokenProvider.generateAccessToken(any(), any(), anyString())).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken(any(), any())).thenReturn("refresh");
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        LocalLoginResponse response = service.authenticate(login("pw"));

        assertThat(response.getToken()).isEqualTo("access");
        assertThat(response.getMfaRequired()).isNull();
    }

    @Test
    void validCodeFinishesTheSignIn() {
        when(mfaService.verifyChallenge("challenge-token")).thenReturn(Optional.of(7));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));
        when(mfaService.verifyCode(7, "123456")).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(any(), any(), anyString())).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken(any(), any())).thenReturn("refresh");

        LocalLoginResponse response = service.authenticateWithMfa("challenge-token", "123456");

        assertThat(response.getToken()).isEqualTo("access");
        assertThat(response.getRefreshToken()).isEqualTo("refresh");
        assertThat(response.getUserId()).isEqualTo(7);
        verify(authAuditRecorder).signedIn(any(), eq(AuthAuditRecorder.Method.PASSWORD), isNull());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void wrongCodeCountsAsAFailedSignInAndIsAudited() {
        when(mfaService.verifyChallenge("challenge-token")).thenReturn(Optional.of(7));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));
        when(mfaService.verifyCode(7, "000000")).thenReturn(false);
        when(loginAttemptService.recordFailure(7)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.authenticateWithMfa("challenge-token", "000000"))
                .isInstanceOf(SignInRefusedException.class)
                .satisfies(e -> assertThat(((SignInRefusedException) e).reason())
                        .isEqualTo(SignInFailures.MFA_CODE_INVALID));
        verify(loginAttemptService).recordFailure(7);
        verify(authAuditRecorder).signInFailed(any(), isNull(), eq(AuthAuditRecorder.Method.PASSWORD), isNull(),
                eq(SignInFailures.MFA_CODE_INVALID));
        verify(jwtTokenProvider, never()).generateAccessToken(any(), any(), anyString());
    }

    @Test
    void expiredChallengeIsRefusedWithoutTouchingTheAccount() {
        when(mfaService.verifyChallenge("stale")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.authenticateWithMfa("stale", "123456"))
                .isInstanceOf(SignInRefusedException.class)
                .hasMessageContaining("expired");
        verify(userRepository, never()).findById(any());
        verify(mfaService, never()).verifyCode(any(), any());
    }

    @Test
    void anAccountDisabledSinceTheFirstStepIsStillRefused() {
        user.setActive(false);
        when(mfaService.verifyChallenge("challenge-token")).thenReturn(Optional.of(7));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.authenticateWithMfa("challenge-token", "123456"))
                .isInstanceOf(SignInRefusedException.class)
                .hasMessageContaining("disabled");
        verify(mfaService, never()).verifyCode(any(), any());
    }
}
