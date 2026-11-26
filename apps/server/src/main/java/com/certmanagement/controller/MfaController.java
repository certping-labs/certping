// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.dto.auth.MfaCodeRequest;
import com.certmanagement.dto.auth.MfaDisableRequest;
import com.certmanagement.dto.auth.MfaLoginRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.AdminUserService;
import com.certmanagement.service.MfaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.certmanagement.security.Permissions.USERS_MANAGE;

/**
 * Two-factor authentication (TOTP) for local accounts: the second sign-in step, and the account's own
 * enrollment. {@code /api/auth/login/mfa} is anonymous like the login itself; the rest need a session.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Two-factor authentication", description = "TOTP enrollment and the second sign-in step")
public class MfaController {

    private final AdminUserService adminUserService;
    private final MfaService mfaService;
    private final UserRepository userRepository;

    @PostMapping(Paths.AUTH_LOGIN_MFA)
    @Operation(summary = "Finish a sign-in with a one-time code",
            description = "Takes the mfaToken a login with mfaRequired=true returned and a six-digit "
                    + "authenticator code or a recovery code. Issues the session tokens.")
    public ResponseEntity<LocalLoginResponse> loginWithMfa(@Valid @RequestBody MfaLoginRequest request) {
        return ResponseEntity.ok(adminUserService.authenticateWithMfa(request.getMfaToken(), request.getCode()));
    }

    @GetMapping(Paths.AUTH_MFA)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Whether the signed-in account has a second factor")
    public ResponseEntity<MfaService.Status> status() {
        return ResponseEntity.ok(mfaService.status(currentUserId()));
    }

    @PostMapping(Paths.AUTH_MFA_ENROLL)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Start enrollment",
            description = "Returns a new secret and otpauth URI for an authenticator app. Nothing is enforced "
                    + "until the enrollment is confirmed with a code.")
    public ResponseEntity<MfaService.Enrollment> enroll() {
        return ResponseEntity.ok(mfaService.enroll(currentUserId()));
    }

    @PostMapping(Paths.AUTH_MFA_CONFIRM)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Confirm enrollment with a code",
            description = "Turns the second factor on and returns the recovery codes. They are shown once.")
    public ResponseEntity<Map<String, Object>> confirm(@Valid @RequestBody MfaCodeRequest request) {
        List<String> recoveryCodes = mfaService.confirm(currentUserId(), request.getCode());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Two-factor authentication is on. Save these recovery codes somewhere safe.");
        body.put("recoveryCodes", recoveryCodes);
        return ResponseEntity.ok(body);
    }

    @DeleteMapping(Paths.AUTH_MFA)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Turn the second factor off", description = "Requires the account's password.")
    public ResponseEntity<Map<String, String>> disable(@Valid @RequestBody MfaDisableRequest request) {
        mfaService.disable(currentUserId(), request.getPassword());
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication is off."));
    }

    @DeleteMapping(Paths.USERS_ID + "/mfa")
    @PreAuthorize("hasPermission(null, '" + USERS_MANAGE + "')")
    @Operation(summary = "Reset a member's second factor",
            description = "For a member who lost the authenticator and the recovery codes. Organization admins "
                    + "can reset members of their own organization; the platform super admin can reset anyone.")
    public ResponseEntity<Map<String, String>> reset(@PathVariable Integer id) {
        User target = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (!OrgResolver.isSuperAdmin()) {
            Long actorOrg = OrgResolver.fromJwtOrNull();
            Long targetOrg = target.getOrganization() == null ? null : target.getOrganization().getId();
            if (actorOrg == null || !actorOrg.equals(targetOrg)) {
                throw new ResourceNotFoundException("User not found");
            }
        }
        boolean removed = mfaService.reset(target);
        return ResponseEntity.ok(Map.of("message", removed
                ? "Two-factor authentication was reset. The member can sign in with their password and enroll again."
                : "The member had no second factor."));
    }

    private Integer currentUserId() {
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            throw new BadRequestException("Cannot resolve user identity from token");
        }
        return userId;
    }
}
