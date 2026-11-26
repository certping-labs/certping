// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateCertificateProfileRequest(
        @NotBlank @Size(max = 200) String name,
        @Size(max = 1000) String description,
        @NotBlank @Size(max = 100) String sourceXref,
        @NotNull ProfileLifecycleStatus lifecycleStatus,
        @NotBlank @Size(max = 80) String targetPlatform,
        @Size(max = 80) String targetVariant,
        @NotNull ProfileKind profileKind,
        @Pattern(regexp = "SCEP|PKCS|NONE") String enrollmentMethod,
        @NotNull @Valid CertificateProfileConfigurationInput configuration
) {
}
