// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.ForgotPasswordRequest;
import com.certmanagement.dto.auth.ResetPasswordRequest;
import com.certmanagement.dto.auth.SetupRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.AccessToken;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import com.certmanagement.service.AdminUserService;
import com.certmanagement.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Local (username and password) accounts: first-run setup of the first Platform Super Admin,
 * password reset by email, and password change. Members are invited by an organization admin
 * (or provisioned by the installation's single sign-on) rather than signing themselves up.
 *
 * <p>The anonymous endpoints are permitted by {@code /api/auth/**} in SecurityConfig. Setup is
 * only answered while no user exists, so after the first admin it is a 409 for everyone.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Local accounts", description = "First-run setup, password reset and password change")
public class LocalAccountController {

    private final AdminUserService adminUserService;
    private final PasswordResetService passwordResetService;
    private final com.certmanagement.service.FirstOrganizationService firstOrganizationService;

    @GetMapping(Paths.AUTH_SETUP_STATUS)
    @Operation(summary = "Whether first-run setup is still needed",
            description = "True until the first Platform Super Admin exists. Public, so the web app can "
                    + "send a fresh installation to the setup screen.")
    public ResponseEntity<Map<String, Object>> setupStatus() {
        return ResponseEntity.ok(Map.of("setupRequired", adminUserService.isSetupRequired()));
    }

    @PostMapping(Paths.AUTH_SETUP)
    @Operation(summary = "Create the first Platform Super Admin",
            description = "Works once, while no user exists. Afterwards it answers 409 and new users are "
                    + "created by administrators.")
    public ResponseEntity<Map<String, Object>> setup(@Valid @RequestBody SetupRequest request) {
        User created = adminUserService.createFirstSuperAdmin(request);
        // The admin signs in straight into an organization, so the product's pages are there.
        firstOrganizationService.ensure();
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "Platform Super Admin created. You can sign in now.",
                "username", created.getUsername(),
                "email", created.getEmail()));
    }

    @PostMapping(Paths.AUTH_FORGOT_PASSWORD)
    @Operation(summary = "Request password reset",
            description = "Always returns 200. If the email matches an active local-auth account and mail is "
                    + "configured, a one-hour reset link is sent.")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        String requestId = RequestContextInterceptor.getCurrentRequestId();
        passwordResetService.forgotPassword(request.getEmail(), requestId);
        return ResponseEntity.ok(Map.of(
                "message", "If an account exists for this email, a reset link has been sent."));
    }

    @PutMapping(Paths.AUTH_RESET_PASSWORD)
    @Operation(summary = "Reset password using a token from the forgot-password email")
    public ResponseEntity<Map<String, String>> resetPassword(@PathVariable("token") String token,
                                                             @Valid @RequestBody ResetPasswordRequest request) {
        String requestId = RequestContextInterceptor.getCurrentRequestId();
        passwordResetService.resetPassword(token, request, requestId);
        return ResponseEntity.ok(Map.of("message", "Password has been reset. You can sign in now."));
    }

    @PostMapping(Paths.AUTH_CHANGE_PASSWORD)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Change password (authenticated)",
            description = "Authenticated users change their own password. Requires the current password.")
    public ResponseEntity<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                                              HttpServletRequest httpRequest) {
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            throw new BadRequestException("Cannot resolve user identity from token");
        }
        adminUserService.changePassword(userId, request, currentAccessToken(httpRequest));
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    /** The verified access token {@link JwtAuthenticationFilter} put on the request, or null. */
    static AccessToken currentAccessToken(HttpServletRequest request) {
        Object token = request == null ? null : request.getAttribute(JwtAuthenticationFilter.ACCESS_TOKEN_ATTRIBUTE);
        return token instanceof AccessToken accessToken ? accessToken : null;
    }
}
