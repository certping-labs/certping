// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A code from the authenticator app, to confirm an enrollment. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaCodeRequest {

    @NotBlank(message = "Code is required")
    private String code;
}
