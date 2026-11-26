// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * One page of devices from the agent ({@code DEVICE_IDENTITY_SYNC_RESPONSE_PART}).
 *
 * <p>Mirrors the agent's {@code DeviceIdentitySyncResponse}. Date fields on nested devices
 * arrive as ISO-8601 strings and are parsed when mapping to {@code DeviceIdentityPayload}.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeviceIdentitySyncResponsePart {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String syncXref;
    private int batchIndex;
    private String batchChecksum;
    private List<DeviceIdentityEntryDto> devices;
    private String respondedAt;

    /**
     * Wire shape of one device — same fields as the agent's {@code DeviceIdentityEntry}
     * / the server's {@code DeviceIdentityPayload}, with string timestamps for MDM dates.
     */
    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class DeviceIdentityEntryDto {
        private String externalId;
        private String entraObjectId;
        private String entraDeviceId;
        private String serialNumber;

        private String deviceName;
        private String managedDeviceName;
        private String operatingSystem;
        private String osVersion;
        private String manufacturer;
        private String model;
        private String deviceCategory;
        private String enrollmentProfileName;

        private String imei;
        private String meid;
        private String wifiMac;

        private String ownerType;
        private String complianceState;
        private String registrationState;
        private String managementAgent;
        private String managementType;
        private String deviceOwnership;
        private String enrollmentType;
        private Boolean isEncrypted;
        private Boolean isSupervised;
        private String jailbrokenState;
        private String mdmEnrolledAt;
        private String mdmLastSyncAt;

        private Map<String, Object> providerAttributes;
    }
}
