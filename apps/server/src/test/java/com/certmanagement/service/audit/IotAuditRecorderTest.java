// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.ProfileLifecycleStatus;
import com.certmanagement.iot.revocation.IotRevocationReason;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * The machine-identity rows as they are stored: each names its device, source, certificate or profile and is
 * referenced by its xref; a source's provider is in words; a profile change names the settings changed, never
 * their values; and a device's identifiers never reach a row.
 */
class IotAuditRecorderTest {

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final IotAuditRecorder iot = new IotAuditRecorder(recorder);

    @BeforeEach
    void inAMembersRequest() {
        GatewayRequestContext.set(7, "42", "req-1", "jane@acme.test");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void deviceRows() {
        IotDevice device = IotDevice.builder().id(1L).deviceXref("dev_1").organizationId(42L)
                .deviceName("Lobby kiosk").serialNumber("SN-SECRET-123").status(DeviceStatus.DECOMMISSIONED).build();
        iot.deviceDecommissioned(device, DeviceStatus.REGISTERED);
        iot.deviceArchived(device);
        iot.deviceRestored(device);

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly("Decommissioned the device 'Lobby kiosk'",
                "Archived the device 'Lobby kiosk'", "Restored the device 'Lobby kiosk' to the inventory");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.category()).isEqualTo("MACHINE_IDENTITY");
            assertThat(row.featureKey()).isEqualTo("IOT_DEVICE_MANAGEMENT");
            assertThat(row.resourceRef()).isEqualTo("dev_1");
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.toString()).doesNotContain("SN-SECRET-123");
        });
        assertThat(rows.get(0).details().changes())
                .containsExactly(new AuditChange("status", "REGISTERED", "DECOMMISSIONED"));
    }

    @Test
    void sourceSyncRowsNameTheProviderInWords() {
        IotDeviceSource source = IotDeviceSource.builder().id(3L).sourceXref("src_1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE).displayName("Corp tenant").build();
        iot.syncStarted(source, "sync_1");
        iot.syncStopped(source);

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Started a device sync from the Microsoft Intune source 'Corp tenant'",
                "Stopped the scheduled device sync from the Microsoft Intune source 'Corp tenant'");
        assertThat(rows.get(0).details().attributes()).containsEntry("syncRef", "sync_1");
        assertThat(IotAuditRecorder.providerName(DeviceSourceProvider.MANUAL)).isNull();
    }

    @Test
    void aRevocationRequestKeepsTheReasonNeverTheOperatorsNote() {
        IotDeviceCertificate certificate = IotDeviceCertificate.builder().id(4L).certificateXref("crt_1")
                .organizationId(42L).commonName("kiosk-01.acme.test").caProvider("ejbca").build();
        iot.certificateRevocationRequested(certificate, IotRevocationReason.KEY_COMPROMISE, "iotrevoke_1");

        AuditEventRow row = rows().get(0);
        assertThat(row.event()).isEqualTo("iot_certificate.revoked");
        assertThat(row.summary()).isEqualTo("Requested the revocation of the device certificate 'kiosk-01.acme.test'");
        assertThat(row.details().attributes()).containsEntry("reason", "KEY_COMPROMISE")
                .containsEntry("caProvider", "EJBCA").containsEntry("operationRef", "iotrevoke_1");
    }

    @Test
    void profileRowsNameTheSettingsChangedNeverTheirValues() {
        CertificateProfile profile = CertificateProfile.builder().id(5L).profileXref("profile_1").organizationId(42L)
                .name("Wi-Fi EAP-TLS").targetPlatform("WINDOWS").lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                .build();
        iot.profileCreated(profile, "src_1");
        iot.profileUpdated(profile, List.of("validityValue", "subjectNameFormat", "not a field; drop table"),
                ProfileLifecycleStatus.DRAFT, true);
        iot.profileDeleted(profile);

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("iot_profile.created", "iot_profile.updated",
                "iot_profile.deleted");
        assertThat(rows).allSatisfy(row -> assertThat(row.featureKey())
                .isEqualTo("IOT_CERTIFICATE_PROFILE_MANAGEMENT"));
        assertThat(rows.get(0).summary()).isEqualTo("Created the certificate profile 'Wi-Fi EAP-TLS'");
        assertThat(rows.get(0).details().attributes()).containsEntry("lifecycleStatus", "ACTIVE")
                .containsEntry("targetPlatform", "WINDOWS").containsEntry("sourceRef", "src_1");
        assertThat(rows.get(1).details().attributes()).containsEntry("changed", "subjectNameFormat, validityValue")
                .containsEntry("sentToProvider", "true");
        assertThat(rows.get(1).details().changes())
                .containsExactly(new AuditChange("lifecycleStatus", "DRAFT", "ACTIVE"));
        assertThat(rows.get(2).summary()).isEqualTo("Deleted the certificate profile 'Wi-Fi EAP-TLS'");
    }

    @Test
    void anEnrollmentThatEndedWithoutACertificateIsAFailureWithTheAgentsCode() {
        IotDeviceSource source = IotDeviceSource.builder().id(3L).sourceXref("src_1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE).displayName("Corp tenant").build();
        iot.enrollmentFailed(42L, source, null, "enr_1", "INTUNE_VALIDATION", false, "CHALLENGE_REJECTED");
        iot.enrollmentFailed(42L, null, "intune-lab", null, "CA_SIGNING", true, null);

        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).recordIsolated(captor.capture());
        List<AuditEventRow> rows = captor.getAllValues();
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "A device certificate enrollment through the Microsoft Intune source 'Corp tenant' ended without"
                        + " a certificate",
                "A device certificate enrollment through the source 'intune-lab' ended without a certificate");
        assertThat(rows).extracting(AuditEventRow::outcome).containsOnly(AuditOutcome.FAILURE);
        assertThat(rows).extracting(AuditEventRow::errorCode).containsExactly("CHALLENGE_REJECTED", "ENROLLMENT_FAILED");
        assertThat(rows.get(0).resourceRef()).isEqualTo("src_1");
        assertThat(rows.get(0).details().attributes()).containsEntry("stage", "INTUNE_VALIDATION")
                .containsEntry("enrollmentRef", "enr_1").containsEntry("retryable", "false");
        assertThat(rows).allSatisfy(row -> assertThat(row.organizationId()).isEqualTo(42L));
    }

    private List<AuditEventRow> rows() {
        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).record(captor.capture());
        return captor.getAllValues();
    }
}
