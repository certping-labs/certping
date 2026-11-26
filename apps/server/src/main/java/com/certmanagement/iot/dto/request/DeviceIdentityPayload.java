// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.request;

import jakarta.validation.constraints.NotBlank;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * One device as supplied by an identity source, already normalised.
 *
 * <p>This is the source-agnostic contract. The agent's Intune adapter produces it from
 * Graph; a script or CSV import can produce it directly. Both doors converge on
 * {@code IotIdentityRegistrationService}, so there is one upsert engine regardless of
 * where the data came from.
 *
 * <p>Callers are expected to have applied the empty-value normalisation described in
 * {@code IntuneFieldMapper} — {@code ""}, {@code "Unknown"}, sentinel dates and the
 * all-zero GUID must already be null by the time they arrive here.
 */
public record DeviceIdentityPayload(

        /** Provider primary id, for example Intune {@code managedDevice.id}. */
        @NotBlank String externalId,

        String entraObjectId,
        String entraDeviceId,
        String serialNumber,

        String deviceName,
        String managedDeviceName,
        String operatingSystem,
        String osVersion,
        String manufacturer,
        String model,
        String deviceCategory,
        String enrollmentProfileName,

        String imei,
        String meid,
        String wifiMac,

        /** COMPANY | PERSONAL | UNKNOWN. Describes the device, not the person. */
        String ownerType,

        String complianceState,
        String registrationState,
        String managementAgent,
        String managementType,
        String deviceOwnership,
        String enrollmentType,
        Boolean isEncrypted,
        Boolean isSupervised,
        /** Tri-state String from Graph, not a boolean. "Unknown" on healthy devices. */
        String jailbrokenState,
        OffsetDateTime mdmEnrolledAt,
        OffsetDateTime mdmLastSyncAt,

        /** Cloud IoT registry attributes; null for MDM sources. */
        ConnectedThingAttributes connectedThing,

        /** Sanitized provider payload with secrets, owner PII and volatile fields removed. */
        Map<String, Object> providerAttributes
) {}
