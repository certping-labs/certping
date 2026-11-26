// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdateCertificateProfileRequest(
        @NotBlank @Size(max = 200) String name,
        @Size(max = 1000) String description,
        @NotNull ProfileLifecycleStatus lifecycleStatus,
        @NotNull Long expectedVersion,
        boolean confirmReissuance,
        @NotNull @Valid CertificateProfileConfigurationInput configuration
) {
}
