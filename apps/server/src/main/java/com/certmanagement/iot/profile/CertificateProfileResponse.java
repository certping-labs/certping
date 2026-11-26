// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.iot.enums.DeviceSourceProvider;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

public record CertificateProfileResponse(
        String profileXref,
        String sourceXref,
        String sourceDisplayName,
        DeviceSourceProvider provider,
        String name,
        String description,
        String targetPlatform,
        String targetVariant,
        String providerProfileType,
        String providerProfileId,
        ProfileLifecycleStatus lifecycleStatus,
        ProfileOrigin profileOrigin,
        ProfileControlMode controlMode,
        ProfileKind profileKind,
        String enrollmentMethod,
        Long desiredRevision,
        Long appliedRevision,
        String latestOperationXref,
        OffsetDateTime latestOperationStartedAt,
        OffsetDateTime latestOperationCompletedAt,
        ProviderSyncStatus providerSyncStatus,
        String providerSyncError,
        OffsetDateTime lastProviderSyncedAt,
        Configuration configuration,
        ProviderSnapshot providerSnapshot,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        Long rowVersion
) {
    public record Configuration(
            String issuerXref,
            String certificateScope,
            String keyAlgorithm,
            Integer keySize,
            String curve,
            String signatureHash,
            String subjectNameFormat,
            List<Map<String, Object>> subjectAltNameFormats,
            List<Map<String, Object>> extendedKeyUsages,
            List<String> keyUsages,
            Integer validityValue,
            String validityUnit,
            Integer renewalWindowDays,
            Boolean keyExportable,
            Map<String, Object> providerConfig
    ) {
    }

    public record ProviderSnapshot(
            Map<String, Object> response,
            int schemaVersion,
            String providerVersion,
            OffsetDateTime providerLastModifiedAt,
            OffsetDateTime providerObservedAt
    ) {
    }
}
