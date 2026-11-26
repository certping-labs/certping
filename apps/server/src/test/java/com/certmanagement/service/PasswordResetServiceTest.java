// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.ResetPasswordRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.AuthNotificationActions;
import com.certmanagement.messaging.AuthNotificationPublisher;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.EmailTokenService;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private EmailTokenService emailTokenService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthNotificationPublisher authNotificationPublisher;
    @Mock private RefreshTokenService refreshTokenService;

    private PasswordResetService service;

    @BeforeEach
    void setUp() {
        PasswordPolicy realPolicy = new PasswordPolicy();
        service = new PasswordResetService(
                userRepository, emailTokenService, passwordEncoder, realPolicy, refreshTokenService, org.mockito.Mockito.mock(AuthAuditRecorder.class));
        ReflectionTestUtils.setField(service, "authNotificationPublisher", authNotificationPublisher);
        ReflectionTestUtils.setField(service, "frontendBaseUrl", "https://app.test.example");
        ReflectionTestUtils.setField(service, "resetExpiryHours", 1);
    }

    // ── forgotPassword anti-enumeration ─────────────────────────────────────

    @Test
    void forgotPassword_is_noop_for_unknown_email() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        service.forgotPassword("ghost@example.com", "req-1");

        verify(authNotificationPublisher, never()).publish(any(), any(), any(), any(), any(), any());
    }

    @Test
    void forgotPassword_is_noop_for_inactive_user() {
        User user = User.builder().id(1).email("a@b.com").active(false).passwordHash("h").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));

        service.forgotPassword("a@b.com", null);

        verify(authNotificationPublisher, never()).publish(any(), any(), any(), any(), any(), any());
    }

    @Test
    void forgotPassword_is_noop_for_sso_managed_user() {
        // IdP-managed user — password lives upstream, no reset email.
        User user = User.builder().id(1).email("a@b.com").active(true)
                .authMethod(User.AuthMethod.SSO).passwordHash(null).build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));

        service.forgotPassword("a@b.com", null);

        verify(authNotificationPublisher, never()).publish(any(), any(), any(), any(), any(), any());
    }

    @Test
    void forgotPassword_publishes_RESET_PASSWORD_for_active_local_user() {
        User user = User.builder().id(7).email("a@b.com").username("alice")
                .active(true).authMethod(User.AuthMethod.LOCAL).passwordHash("h").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
        when(emailTokenService.issuePasswordResetToken(eq("a@b.com"), any())).thenReturn("tok");

        service.forgotPassword("a@b.com", "req-2");

        verify(authNotificationPublisher).publish(
                eq(AuthNotificationActions.RESET_PASSWORD),
                eq("a@b.com"), eq(7), any(), any(), eq("req-2"));
    }

    @Test
    void forgotPassword_publishes_RESET_PASSWORD_for_local_user_with_no_password() {
        // A local account with no password yet (a member an admin added, say): forgot-password
        // acts as the initial set-password flow for it.
        User user = User.builder().id(8).email("a@b.com").username("alice")
                .active(true).authMethod(User.AuthMethod.LOCAL).passwordHash(null).build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
        when(emailTokenService.issuePasswordResetToken(eq("a@b.com"), any())).thenReturn("tok");

        service.forgotPassword("a@b.com", "req-3");

        verify(authNotificationPublisher).publish(
                eq(AuthNotificationActions.RESET_PASSWORD),
                eq("a@b.com"), eq(8), any(), any(), eq("req-3"));
    }

    @Test
    void forgotPassword_email_failure_does_not_propagate() {
        User user = User.builder().id(7).email("a@b.com").username("alice")
                .active(true).authMethod(User.AuthMethod.LOCAL).passwordHash("h").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
        when(emailTokenService.issuePasswordResetToken(anyString(), any())).thenThrow(new RuntimeException("queue down"));

        // Must NOT throw — caller (controller) always returns 200 to avoid enumeration.
        service.forgotPassword("a@b.com", null);
    }

    // ── resetPassword ──────────────────────────────────────────────────────

    @Test
    void resetPassword_rejects_password_mismatch() {
        ResetPasswordRequest req = ResetPasswordRequest.builder()
                .newPassword("Aa1@aaaa").confirmPassword("Different1!").build();

        assertThatThrownBy(() -> service.resetPassword("tok", req, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("do not match");
    }

    @Test
    void resetPassword_rejects_expired_token() {
        ResetPasswordRequest req = matchingRequest();
        when(emailTokenService.parsePasswordResetToken("tok"))
                .thenThrow(new EmailTokenService.EmailTokenException(
                        EmailTokenService.EmailTokenError.EXPIRED, "expired"));

        assertThatThrownBy(() -> service.resetPassword("tok", req, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void resetPassword_rejects_invalid_token() {
        ResetPasswordRequest req = matchingRequest();
        when(emailTokenService.parsePasswordResetToken("tok"))
                .thenThrow(new EmailTokenService.EmailTokenException(
                        EmailTokenService.EmailTokenError.INVALID, "bad"));

        assertThatThrownBy(() -> service.resetPassword("tok", req, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("invalid");
    }

    @Test
    void resetPassword_refuses_a_token_bound_to_an_earlier_password() {
        // The token was issued against OLDHASH; the password has changed since (by this very token's use, or
        // otherwise), so replaying it must fail and leave the account alone.
        when(emailTokenService.parsePasswordResetToken("tok")).thenReturn(new EmailTokenService.ParsedEmailToken(
                "a@b.com", "jti", EmailTokenService.passwordFingerprint("OLDHASH")));
        User user = User.builder().id(7).email("a@b.com").username("alice").active(true)
                .authMethod(User.AuthMethod.LOCAL).passwordHash("NEWHASH").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.resetPassword("tok", matchingRequest(), null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Reset link is invalid.");
        assertThat(user.getPasswordHash()).isEqualTo("NEWHASH");
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void resetPassword_refuses_a_token_without_the_password_binding() {
        when(emailTokenService.parsePasswordResetToken("tok"))
                .thenReturn(new EmailTokenService.ParsedEmailToken("a@b.com", "jti"));
        User user = User.builder().id(7).email("a@b.com").username("alice").active(true)
                .authMethod(User.AuthMethod.LOCAL).passwordHash("h").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.resetPassword("tok", matchingRequest(), null))
                .isInstanceOf(BadRequestException.class);
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void resetPassword_refuses_inactive_deleted_and_sso_accounts() {
        String bound = EmailTokenService.passwordFingerprint("h");
        when(emailTokenService.parsePasswordResetToken("tok"))
                .thenReturn(new EmailTokenService.ParsedEmailToken("a@b.com", "jti", bound));
        for (User user : java.util.List.of(
                User.builder().id(7).email("a@b.com").active(false).authMethod(User.AuthMethod.LOCAL).passwordHash("h").build(),
                User.builder().id(7).email("a@b.com").active(true).isDeleted(true).authMethod(User.AuthMethod.LOCAL).passwordHash("h").build(),
                User.builder().id(7).email("a@b.com").active(true).authMethod(User.AuthMethod.SSO).passwordHash("h").build())) {
            when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
            assertThatThrownBy(() -> service.resetPassword("tok", matchingRequest(), null))
                    .isInstanceOf(BadRequestException.class);
        }
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void resetPassword_ends_every_session_through_the_revocation_service() {
        SessionRevocationService revocation = org.mockito.Mockito.mock(SessionRevocationService.class);
        ReflectionTestUtils.setField(service, "sessionRevocationService", revocation);
        when(emailTokenService.parsePasswordResetToken("tok")).thenReturn(new EmailTokenService.ParsedEmailToken(
                "a@b.com", "jti", EmailTokenService.passwordFingerprint("h")));
        User user = User.builder().id(7).email("a@b.com").username("alice").active(true)
                .authMethod(User.AuthMethod.LOCAL).passwordHash("h").build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("Aa1@aaaa")).thenReturn("NEWHASH");

        service.resetPassword("tok", matchingRequest(), null);

        verify(revocation).endAllSessions(7, null);
    }

    @Test
    void resetPassword_updates_hash_clears_lockout_and_revokes_tokens() {
        ResetPasswordRequest req = matchingRequest();
        when(emailTokenService.parsePasswordResetToken("tok")).thenReturn(new EmailTokenService.ParsedEmailToken(
                "a@b.com", "jti", EmailTokenService.passwordFingerprint(null)));
        User user = User.builder().id(7).email("a@b.com").username("alice").active(true)
                .authMethod(User.AuthMethod.LOCAL).failedLoginAttempts(3).build();
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("Aa1@aaaa")).thenReturn("NEWHASH");

        service.resetPassword("tok", req, "req-3");

        assertThat(user.getPasswordHash()).isEqualTo("NEWHASH");
        // The lockout is cleared by statement: the entity never writes those columns.
        verify(userRepository).clearFailedLogins(eq(7), any());
        assertThat(user.getMustChangePassword()).isFalse();

        // Force re-login everywhere.
        verify(refreshTokenService).revokeAllForUser(7);

        // Confirmation email.
        verify(authNotificationPublisher).publish(
                eq(AuthNotificationActions.PASSWORD_CHANGE_SUCCESS),
                eq("a@b.com"), eq(7), any(), any(), eq("req-3"));
    }

    private ResetPasswordRequest matchingRequest() {
        return ResetPasswordRequest.builder()
                .newPassword("Aa1@aaaa").confirmPassword("Aa1@aaaa").build();
    }
}
