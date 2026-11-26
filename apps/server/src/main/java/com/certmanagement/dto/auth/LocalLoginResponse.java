// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.Set;

/**
 * Response containing local user authentication result.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LocalLoginResponse {

    private String token;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;

    private Integer userId;
    private String username;
    private String email;
    private Long organizationId;
    private String organizationName;
    private Set<String> roles;
    private Set<String> permissions;
    private Boolean mustChangePassword;

    private OffsetDateTime lastLoginAt;

    /**
     * True when the password was right but the account has a second factor: no tokens are issued yet, and
     * the client finishes with {@code POST /api/auth/login/mfa} using {@link #mfaToken}.
     */
    private Boolean mfaRequired;

    /** The short-lived challenge the second step presents; null unless {@link #mfaRequired}. */
    private String mfaToken;
}
