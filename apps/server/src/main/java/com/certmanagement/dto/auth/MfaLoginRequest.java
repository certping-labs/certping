// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Second step of a password sign-in: the challenge token the first step returned and a code. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaLoginRequest {

    @NotBlank(message = "mfaToken is required")
    private String mfaToken;

    /** A six-digit authenticator code, or a recovery code. */
    @NotBlank(message = "Code is required")
    private String code;
}
