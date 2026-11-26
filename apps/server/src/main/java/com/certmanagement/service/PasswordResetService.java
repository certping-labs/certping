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
import com.certmanagement.security.SignInAccount;
import com.certmanagement.service.audit.AuthAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Handles forgot-password and reset-password flows. Tokens are stateless HS256 JWTs signed
 * with a dedicated secret (see {@link EmailTokenService}).
 *
 * <p>{@link #forgotPassword(String, String)} always returns successfully — by design, to avoid
 * leaking whether an email is registered. The controller wraps it with a fixed 200 response.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final EmailTokenService emailTokenService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final RefreshTokenService refreshTokenService;
    private final AuthAuditRecorder authAuditRecorder;

    @Autowired(required = false)
    private AuthNotificationPublisher authNotificationPublisher;

    /** Field-injected so constructor-built tests keep working; without it only refresh tokens are revoked. */
    @Autowired(required = false)
    private SessionRevocationService sessionRevocationService;

    @Value("${app.frontend-base-url:}")
    private String frontendBaseUrl;

    @Value("${jwt.password-reset-expiry-hours:1}")
    private int resetExpiryHours;

    /** Generate + email a reset token. No-op for missing/inactive users (anti-enumeration). */
    @Transactional
    public void forgotPassword(String emailRaw, String requestId) {
        String email = normalizeEmail(emailRaw);
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            log.debug("forgot-password: unknown email, no-op");
            return;
        }
        User user = userOpt.get();
        if (!Boolean.TRUE.equals(user.getActive())) {
            log.debug("forgot-password: inactive user, no-op");
            return;
        }
        if (user.getAuthMethod() == User.AuthMethod.SSO) {
            // IdP-managed account: the password lives in the IdP, not here.
            log.debug("forgot-password: SSO-managed account, no-op (userId={})", user.getId());
            return;
        }

        if (authNotificationPublisher == null) {
            log.warn("AuthNotificationPublisher unavailable — skipping forgot-password email for userId={}", user.getId());
            return;
        }
        try {
            String token = emailTokenService.issuePasswordResetToken(user.getEmail(), user.getPasswordHash());
            String link = buildResetLink(token);
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("resetLink", link);
            fields.put("username", user.getUsername());
            fields.put("expiryHours", resetExpiryHours);

            Long orgId = user.getOrganization() != null ? user.getOrganization().getId() : null;
            authNotificationPublisher.publish(
                    AuthNotificationActions.RESET_PASSWORD,
                    user.getEmail(), user.getId(), orgId, fields, requestId);
        } catch (Exception e) {
            log.error("Failed to publish forgot-password email for userId={}: {}", user.getId(), e.getMessage(), e);
            return;
        }
        // Only once the email was handed off, and queued rather than written here: the answer must be the
        // same for every email, whether or not a row could be written.
        authAuditRecorder.passwordResetRequested(SignInAccount.of(user));
    }

    /** Validate the reset token and apply the new password. */
    @Transactional
    public void resetPassword(String token, ResetPasswordRequest request, String requestId) {
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        EmailTokenService.ParsedEmailToken parsed;
        try {
            parsed = emailTokenService.parsePasswordResetToken(token);
        } catch (EmailTokenService.EmailTokenException e) {
            if (e.getError() == EmailTokenService.EmailTokenError.EXPIRED) {
                throw new BadRequestException("Reset link has expired. Request a new one.");
            }
            throw new BadRequestException("Reset link is invalid.");
        }

        User user = userRepository.findByEmail(normalizeEmail(parsed.getEmail()))
                .orElseThrow(() -> new BadRequestException("Reset link is invalid."));

        // Single use: the token names the password hash it was issued against, so a used token (the reset
        // changed the hash), an older one, or one from before any other password change no longer matches.
        // A token without the claim predates this binding and is refused.
        String bound = parsed.getPasswordFingerprint();
        if (bound == null || !java.security.MessageDigest.isEqual(
                bound.getBytes(StandardCharsets.UTF_8),
                EmailTokenService.passwordFingerprint(user.getPasswordHash()).getBytes(StandardCharsets.UTF_8))) {
            log.info("AUTH_EVENT password-reset refused userId={} reason=token_used_or_superseded", user.getId());
            throw new BadRequestException("Reset link is invalid.");
        }
        // The same accounts forgot-password would not mail: a disabled, deleted or IdP-managed account
        // cannot be given a local password through a link.
        if (!Boolean.TRUE.equals(user.getActive()) || Boolean.TRUE.equals(user.getIsDeleted())
                || user.getAuthMethod() == User.AuthMethod.SSO) {
            log.info("AUTH_EVENT password-reset refused userId={} reason=account_not_resettable", user.getId());
            throw new BadRequestException("Reset link is invalid.");
        }

        // Apply policy with the user's own username/email as context to block trivial matches.
        passwordPolicy.validate(request.getNewPassword(), user.getUsername(), user.getEmail());

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setMustChangePassword(false);
        userRepository.save(user);
        // A new password lifts a lockout; the counter is written by statement, never by the entity.
        userRepository.clearFailedLogins(user.getId(), OffsetDateTime.now(ZoneOffset.UTC));

        // Force re-login everywhere: every refresh token is revoked and every access token refused.
        if (sessionRevocationService != null) {
            sessionRevocationService.endAllSessions(user.getId(), null);
        } else {
            refreshTokenService.revokeAllForUser(user.getId());
        }
        authAuditRecorder.passwordResetCompleted(SignInAccount.of(user));
        log.info("AUTH_EVENT password-reset success userId={}", user.getId());

        // Notify the user that their password just changed (best-effort).
        if (authNotificationPublisher != null) {
            try {
                Map<String, Object> fields = new LinkedHashMap<>();
                fields.put("username", user.getUsername());
                Long orgId = user.getOrganization() != null ? user.getOrganization().getId() : null;
                authNotificationPublisher.publish(
                        AuthNotificationActions.PASSWORD_CHANGE_SUCCESS,
                        user.getEmail(), user.getId(), orgId, fields, requestId);
            } catch (Exception e) {
                log.error("Failed to publish reset-success email for userId={}: {}", user.getId(), e.getMessage(), e);
            }
        }
    }

    private String buildResetLink(String token) {
        String base = (frontendBaseUrl != null && !frontendBaseUrl.isBlank())
                ? stripTrailingSlash(frontendBaseUrl) : "";
        return base + "/reset-password?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    }

    private String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
