// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;
import java.util.Map;

/** Complete non-history view of one device registry record and its optional facets. */
public record DeviceDetail(
        String deviceXref,
        Source source,
        String sourceDeviceId,
        Map<String, Object> sourceIdentifiers,
        String deviceClass,
        String serialNumber,
        String deviceName,
        String manufacturer,
        String model,
        String ownership,
        String status,
        /** Hidden from the inventory by an operator. The row and its history are intact. */
        boolean archived,
        OffsetDateTime registeredAt,
        OffsetDateTime lastSeenInSourceAt,
        OffsetDateTime decommissionedAt,
        EndpointPosture endpointPosture,
        ConnectedThing connectedThing,
        Owner owner,
        ProviderData providerData,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {
    public record Source(
            String sourceXref,
            String provider,
            String sourceCategory,
            String connectionProfileRef,
            String displayName,
            String description,
            Map<String, Object> configurationMetadata,
            boolean syncEnabled,
            String status
    ) {}

    public record EndpointPosture(
            String operatingSystem,
            String osVersion,
            String complianceState,
            String complianceStateRaw,
            Boolean encrypted,
            Boolean supervised,
            String jailbrokenState,
            String managementAgent,
            String enrollmentType,
            OffsetDateTime mdmEnrolledAt,
            OffsetDateTime mdmLastSyncAt,
            Map<String, Object> vendorAttributes
    ) {}

    public record ConnectedThing(
            String attestationType,
            String hubOrAccountRef,
            String thingType,
            String formFactor,
            String connectivityState,
            OffsetDateTime lastConnectedAt,
            Map<String, Object> customAttributes
    ) {}

    public record Owner(
            String upn,
            String email,
            String displayName,
            OffsetDateTime updatedAt
    ) {}

    public record ProviderData(
            int schemaVersion,
            OffsetDateTime updatedAt,
            Map<String, Object> attributes
    ) {}
}
