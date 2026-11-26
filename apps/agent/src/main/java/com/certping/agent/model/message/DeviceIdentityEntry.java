// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * One device, already normalised by {@code ManagedDeviceMapper}.
 *
 * <p>Mirrors the server's {@code DeviceIdentityPayload}. Graph's empty-value quirks are
 * resolved before this leaves the agent, so the server receives plain nulls.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DeviceIdentityEntry {
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
