// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Turning the second factor off takes the account's password, so a left-open session cannot do it alone. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaDisableRequest {

    @NotBlank(message = "Password is required")
    private String password;
}
