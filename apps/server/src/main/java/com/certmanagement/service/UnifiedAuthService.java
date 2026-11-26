// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.User;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.SignInRefusedException;
import com.certmanagement.service.audit.AuthAuditRecorder;
import com.certmanagement.security.SignInFailures;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Optional;

/**
 * Login entry point that accepts email OR username and delegates to {@link AdminUserService}.
 *
 * Disambiguation: if the input contains '@' we look up by email (globally unique),
 * otherwise we look up by username (already globally unique). Once we have a user, we hand off
 * the request to {@code AdminUserService.authenticate()} which keeps the password check, lockout,
 * and token issuance behavior in one place.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UnifiedAuthService {

    private final UserRepository userRepository;
    private final AdminUserService adminUserService;
    private final AuthAuditRecorder authAuditRecorder;

    private static final AuditReason INVALID_CREDENTIALS = SignInFailures.INVALID_CREDENTIALS;

    public LocalLoginResponse login(UnifiedLoginRequest request) {
        String identifier = request.getIdentifier().trim();
        Optional<User> userOpt = identifier.contains("@")
                ? userRepository.findByEmail(identifier.toLowerCase(Locale.ROOT))
                : userRepository.findByUsername(identifier);

        if (userOpt.isEmpty()) {
            // Same opaque error AdminUserService.authenticate returns — no enumeration. The audit row is
            // internal and anonymous: it never stores the identifier that was typed.
            // A password check all the same, so the answer takes as long as a wrong password's.
            adminUserService.spendPasswordCheck(request.getPassword());
            authAuditRecorder.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, INVALID_CREDENTIALS);
            throw new SignInRefusedException(INVALID_CREDENTIALS, null, "Invalid username or password");
        }

        // AdminUserService.authenticate expects a username, so feed it the resolved username.
        LocalLoginRequest delegated = LocalLoginRequest.builder()
                .username(userOpt.get().getUsername())
                .password(request.getPassword())
                .build();
        return adminUserService.authenticate(delegated);
    }
}
