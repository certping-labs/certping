// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

public record CertificateProfileConfigurationInput(
        @Size(max = 100) String issuerXref,
        @Pattern(regexp = "DEVICE|USER") String certificateScope,
        @Pattern(regexp = "RSA|EC") String keyAlgorithm,
        @Min(256) @Max(16384) Integer keySize,
        @Size(max = 50) String curve,
        @Size(max = 30) String signatureHash,
        @Size(max = 1000) String subjectNameFormat,
        @Size(max = 20) List<Map<String, Object>> subjectAltNameFormats,
        @Size(max = 20) List<Map<String, Object>> extendedKeyUsages,
        @Size(max = 10) List<String> keyUsages,
        @Min(1) Integer validityValue,
        @Pattern(regexp = "DAYS|MONTHS|YEARS") String validityUnit,
        @Min(0) Integer renewalWindowDays,
        Boolean keyExportable,
        Map<String, Object> providerConfig
) {
}
