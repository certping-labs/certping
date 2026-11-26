// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.model.message.DeviceIdentityEntry;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ManagedDeviceMapperTest {
    private static final String ZERO_GUID = "00000000-0000-0000-0000-000000000000";
    private final ManagedDeviceMapper mapper = new ManagedDeviceMapper();

    private static Map<String, Object> managedDevice() {
        Map<String, Object> device = new LinkedHashMap<>();
        device.put("id", "intune-device-1");
        device.put("azureADDeviceId", "entra-device-1");
        device.put("serialNumber", "C02TEST0001");
        device.put("deviceName", "Alex’s MacBook Air");
        device.put("operatingSystem", "macOS");
        device.put("osVersion", "15.6.1");
        device.put("managedDeviceOwnerType", "company");
        device.put("complianceState", "compliant");
        device.put("lastSyncDateTime", "2026-08-21T09:02:11.123Z");
        device.put("userId", "user-1");
        device.put("userPrincipalName", "alex@contoso.example");
        device.put("userDisplayName", "Alex Example");
        device.put("emailAddress", "alex@contoso.example");
        return device;
    }

    @Test
    void mapsStableIdentityAndEntraEnrichment() {
        Map<String, Map<String, Object>> entra = Map.of("entra-device-1", Map.of(
                "id", "entra-object-1", "managementType", "MDM", "deviceOwnership", "Company"));

        DeviceIdentityEntry entry = mapper.toEntry(managedDevice(), entra);

        assertThat(entry.getExternalId()).isEqualTo("intune-device-1");
        assertThat(entry.getSerialNumber()).isEqualTo("C02TEST0001");
        assertThat(entry.getDeviceName()).isEqualTo("Alex’s MacBook Air");
        assertThat(entry.getOwnerType()).isEqualTo("COMPANY");
        assertThat(entry.getEntraObjectId()).isEqualTo("entra-object-1");
        assertThat(entry.getManagementType()).isEqualTo("MDM");
        assertThat(entry.getMdmLastSyncAt()).isEqualTo("2026-08-21T09:02:11Z");
    }

    @Test
    void normalizesGraphSentinelsAndEmptyValues() {
        Map<String, Object> device = new LinkedHashMap<>();
        device.put("id", "stale-device");
        device.put("azureADDeviceId", ZERO_GUID);
        device.put("serialNumber", "");
        device.put("osVersion", "0.0.0.0");
        device.put("deviceCategoryDisplayName", "Unknown");
        device.put("lastSyncDateTime", "0001-01-01T00:00:00Z");

        DeviceIdentityEntry entry = mapper.toEntry(device, Map.of());

        assertThat(entry.getExternalId()).isEqualTo("stale-device");
        assertThat(entry.getEntraDeviceId()).isNull();
        assertThat(entry.getSerialNumber()).isNull();
        assertThat(entry.getOsVersion()).isNull();
        assertThat(entry.getDeviceCategory()).isNull();
        assertThat(entry.getMdmLastSyncAt()).isNull();
    }

    @Test
    void providerAttributesAllowlistUsefulOperationalDataWithoutIdentifiersOrPii() {
        Map<String, Object> device = managedDevice();
        device.put("activationLockBypassCode", "sensitive-bypass-code");
        device.put("freeStorageSpaceInBytes", 100L);
        device.put("wiFiMacAddress", "00:11:22:33:44:55");
        device.put("imei", "device-identifier");
        device.put("managementState", "managed");
        device.put("easActivated", false);
        device.put("azureADRegistered", true);
        device.put("enrollmentProfileName", "Corporate macOS");
        device.put("partnerReportedThreatState", "unknown");
        device.put("requireUserEnrollmentApproval", true);
        device.put("managementCertificateExpirationDate", "2027-08-20T21:15:08Z");
        device.put("complianceGracePeriodExpirationDateTime", "9999-12-31T23:59:59Z");
        device.put("customProviderField", "not-allowlisted");

        DeviceIdentityEntry entry = mapper.toEntry(device, Map.of());
        Map<String, Object> attributes = entry.getProviderAttributes();

        assertThat(attributes)
                .containsEntry("managementState", "managed")
                .containsEntry("easActivated", false)
                .containsEntry("azureADRegistered", true)
                .containsEntry("enrollmentProfileName", "Corporate macOS")
                .containsEntry("partnerReportedThreatState", "unknown")
                .containsEntry("requireUserEnrollmentApproval", true)
                .containsEntry("managementCertificateExpiresAt", "2027-08-20T21:15:08Z");
        assertThat(attributes).doesNotContainKeys(
                "activationLockBypassCode", "freeStorageSpaceInBytes",
                "userId", "userPrincipalName", "userDisplayName", "emailAddress",
                "wiFiMacAddress", "imei", "customProviderField",
                "complianceGracePeriodExpiresAt");
        assertThat(entry.getWifiMac()).isEqualTo("00:11:22:33:44:55");
        assertThat(entry.getImei()).isEqualTo("device-identifier");
        assertThat(device).containsKeys("activationLockBypassCode", "userPrincipalName");
    }

    @Test
    void handlesMissingOrMalformedOptionalValues() {
        Map<String, Object> device = new LinkedHashMap<>();
        device.put("id", "only-an-id");
        device.put("enrolledDateTime", "not-a-date");

        DeviceIdentityEntry entry = mapper.toEntry(device, Map.of());

        assertThat(entry.getExternalId()).isEqualTo("only-an-id");
        assertThat(entry.getSerialNumber()).isNull();
        assertThat(entry.getMdmEnrolledAt()).isNull();
    }
}
