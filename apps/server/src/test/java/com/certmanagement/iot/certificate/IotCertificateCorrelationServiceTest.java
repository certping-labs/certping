// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateCorrelationServiceTest {
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-08-27T12:00:00Z");
    private static final IotDeviceSource SOURCE = IotDeviceSource.builder()
            .id(9L).organizationId(42L).sourceXref("src_1")
            .connectionProfileRef("intune-primary").build();

    @Mock private IotCertificateEnrollmentRepository enrollmentRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceEventService eventService;
    @Spy private ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    @Mock private IotCertificateSupersessionService supersessionService;
    @InjectMocks private IotCertificateCorrelationService service;

    private static IotCertificateEnrollment pending(String identifierAssurance, String identifierType) {
        return IotCertificateEnrollment.builder()
                .id(101L).enrollmentXref("enr_1").organizationId(42L).deviceSourceId(9L)
                .assertedSourceDeviceId("device-guid")
                .sourceIdentifierType(identifierType)
                .sourceIdentifierAssurance(identifierAssurance)
                .deviceMatchStatus("DEVICE_NOT_SYNCED")
                .build();
    }

    private static final String ENTRA_DEVICE_ID = "0e1d2c3b-0000-4000-8000-00000000d001";
    private static final OffsetDateTime SYNC_STARTED_AT =
            OffsetDateTime.parse("2026-08-27T11:00:00Z");

    private static IotDevice device(long id, String xref, String entraDeviceId) {
        return IotDevice.builder().id(id).deviceXref(xref)
                .sourceDeviceId("intune-" + id)
                .sourceIdentifiersJson(entraDeviceId == null ? null
                        : "{\"entraDeviceId\":\"" + entraDeviceId + "\"}")
                .build();
    }

    private static IotCertificateEnrollment linked(
            long id, String xref, long deviceId, String deviceMatchStatus) {
        return IotCertificateEnrollment.builder()
                .id(id).enrollmentXref(xref).organizationId(42L).deviceSourceId(9L)
                .deviceId(deviceId).deviceMatchStatus(deviceMatchStatus).build();
    }

    @Test
    void movesTheLiveShapedCertificateFromDeviceFourToReenrolledDeviceFive() {
        IotDevice oldDevice = device(4L, "dev_old", ENTRA_DEVICE_ID);
        IotDevice newDevice = device(5L, "dev_new", ENTRA_DEVICE_ID);
        IotCertificateEnrollment enrollment = linked(101L, "enr_live", 4L, "MATCHED");
        IotDeviceCertificate certificate = IotDeviceCertificate.builder()
                .id(202L).certificateXref("crt_0a8c").enrollmentId(101L).deviceId(4L).build();
        when(enrollmentRepository.findRepairableLinkIds(eq(List.of(4L)), eq(NOW), anyInt()))
                .thenReturn(List.of(enrollment.getId()));
        when(enrollmentRepository.lockLinksForRepair(List.of(enrollment.getId())))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredByEntraDeviceIds(9L, SYNC_STARTED_AT, List.of(ENTRA_DEVICE_ID)))
                .thenReturn(List.of(newDevice));
        when(certificateRepository.lockByEnrollmentIdIn(List.of(101L)))
                .thenReturn(List.of(certificate));

        int rebound = service.relinkFromOrphanedDevices(9L, SYNC_STARTED_AT, List.of(oldDevice), NOW, "sync-1");

        assertThat(rebound).isEqualTo(1);
        assertThat(enrollment.getDeviceId()).isEqualTo(5L);
        assertThat(certificate.getDeviceId()).isEqualTo(5L);
        verify(enrollmentRepository).saveAll(List.of(enrollment));
        verify(certificateRepository).saveAll(List.of(certificate));
        verify(eventService).recordEnrollment(eq(enrollment),
                eq(DeviceEventType.CERTIFICATE_DEVICE_MATCHED), eq("REBOUND"), any(), any(),
                eq("sync-1"), eq("scep-device-orphan-reconcile:enr_live:dev_new"), eq(NOW));
    }

    @Test
    void trueRenewalWithoutAnAssertedIdentifierUsesThePriorDevicesEntraIdentity() {
        IotDevice oldDevice = device(4L, "dev_old", ENTRA_DEVICE_ID);
        IotDevice newDevice = device(5L, "dev_new", ENTRA_DEVICE_ID);
        IotCertificateEnrollment enrollment =
                linked(102L, "enr_renewal", 4L, "INHERITED_FROM_RENEWAL");
        IotDeviceCertificate certificate = IotDeviceCertificate.builder()
                .id(203L).certificateXref("crt_renewal").enrollmentId(102L).deviceId(4L).build();
        when(enrollmentRepository.findRepairableLinkIds(eq(List.of(4L)), eq(NOW), anyInt()))
                .thenReturn(List.of(enrollment.getId()));
        when(enrollmentRepository.lockLinksForRepair(List.of(enrollment.getId())))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredByEntraDeviceIds(9L, SYNC_STARTED_AT, List.of(ENTRA_DEVICE_ID)))
                .thenReturn(List.of(newDevice));
        when(certificateRepository.lockByEnrollmentIdIn(List.of(102L)))
                .thenReturn(List.of(certificate));

        int rebound = service.relinkFromOrphanedDevices(9L, SYNC_STARTED_AT, List.of(oldDevice), NOW, "sync-1");

        assertThat(rebound).isEqualTo(1);
        assertThat(enrollment.getDeviceId()).isEqualTo(5L);
        assertThat(certificate.getDeviceId()).isEqualTo(5L);
    }

    @Test
    void noRegisteredReplacementKeepsTheHistoricalLinkOnTheOrphanedDevice() {
        IotDevice oldDevice = device(4L, "dev_old", ENTRA_DEVICE_ID);
        IotCertificateEnrollment enrollment = linked(101L, "enr_live", 4L, "MATCHED");
        when(enrollmentRepository.findRepairableLinkIds(eq(List.of(4L)), eq(NOW), anyInt()))
                .thenReturn(List.of(enrollment.getId()));
        when(enrollmentRepository.lockLinksForRepair(List.of(enrollment.getId())))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredByEntraDeviceIds(9L, SYNC_STARTED_AT, List.of(ENTRA_DEVICE_ID)))
                .thenReturn(List.of());
        when(certificateRepository.lockByEnrollmentIdIn(List.of(101L))).thenReturn(List.of());

        int rebound = service.relinkFromOrphanedDevices(9L, SYNC_STARTED_AT, List.of(oldDevice), NOW, "sync-1");

        assertThat(rebound).isZero();
        assertThat(enrollment.getDeviceId()).isEqualTo(4L);
        verifyNoInteractions(eventService);
    }

    @Test
    void severalRegisteredMatchesKeepTheHistoricalLinkRatherThanGuess() {
        IotDevice oldDevice = device(4L, "dev_old", ENTRA_DEVICE_ID);
        IotCertificateEnrollment enrollment = linked(101L, "enr_live", 4L, "MATCHED");
        when(enrollmentRepository.findRepairableLinkIds(eq(List.of(4L)), eq(NOW), anyInt()))
                .thenReturn(List.of(enrollment.getId()));
        when(enrollmentRepository.lockLinksForRepair(List.of(enrollment.getId())))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredByEntraDeviceIds(9L, SYNC_STARTED_AT, List.of(ENTRA_DEVICE_ID)))
                .thenReturn(List.of(device(5L, "dev_new", ENTRA_DEVICE_ID),
                        device(6L, "dev_other", ENTRA_DEVICE_ID)));
        when(certificateRepository.lockByEnrollmentIdIn(List.of(101L))).thenReturn(List.of());

        int rebound = service.relinkFromOrphanedDevices(9L, SYNC_STARTED_AT, List.of(oldDevice), NOW, "sync-1");

        assertThat(rebound).isZero();
        assertThat(enrollment.getDeviceId()).isEqualTo(4L);
        verifyNoInteractions(eventService);
    }

    @Test
    void anOrphanedDeviceWithoutAnEntraIdentityIsNeverRepairedFromWeakIdentifiers() {
        int rebound = service.relinkFromOrphanedDevices(
                9L, SYNC_STARTED_AT, List.of(device(4L, "dev_old", null)), NOW, "sync-1");

        assertThat(rebound).isZero();
        verifyNoInteractions(enrollmentRepository, deviceRepository, certificateRepository);
    }

    @Test
    void relinksEnrollmentAndCertificateWhenTheDeviceArrived() {
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "MANAGED_DEVICE_ID");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceDeviceId(9L, "device-guid"))
                .thenReturn(Optional.of(IotDevice.builder().id(11L).build()));
        IotDeviceCertificate certificate = IotDeviceCertificate.builder().id(202L).build();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.of(certificate));

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isEqualTo(11L);
        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("MATCHED");
        assertThat(certificate.getDeviceId()).isEqualTo(11L);
        verify(enrollmentRepository).save(enrollment);
        verify(certificateRepository).save(certificate);
        verify(eventService).recordEnrollment(eq(enrollment),
                eq(DeviceEventType.CERTIFICATE_DEVICE_MATCHED), eq("MATCHED"),
                any(), any(), eq("corr-1"), eq("scep-device-relink:enr_1"), eq(NOW));
    }

    @Test
    void deviceStillMissingLeavesTheEnrollmentPending() {
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "MANAGED_DEVICE_ID");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceDeviceId(9L, "device-guid"))
                .thenReturn(Optional.empty());

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isNull();
        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("DEVICE_NOT_SYNCED");
        verify(enrollmentRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void anUnverifiedIdentifierIsNeverRelinkedEvenIfQueued() {
        // Defense in depth: DEVICE_NOT_SYNCED should only ever hold validated managed-device ids,
        // but a row that violates that must not silently gain a device link.
        IotCertificateEnrollment enrollment = pending("ASSERTED", "MANAGED_DEVICE_ID");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        verify(deviceRepository, never()).findRegisteredBySourceScopedIdentifier(any(), any());
        verify(enrollmentRepository, never()).save(any());
    }

    @Test
    void anUndeterminedNamespaceIdentifierRelinksViaTheEntraKey() {
        // The CSR subject carried the Entra device id; the device row is keyed by the Intune id.
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "UNKNOWN");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(9L, "device-guid"))
                .thenReturn(List.of(IotDevice.builder().id(11L).build()));
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isEqualTo(11L);
        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("MATCHED");
    }

    /**
     * Recorded even on a partial sync. Leaving it DEVICE_NOT_SYNCED would keep it in the half of
     * the bounded window reserved for rows still waiting for their device, which is taken oldest
     * first — a tenant whose syncs are usually partial would fill that half with rows that cannot
     * resolve. It is safe to record because the verdict is no longer terminal.
     */
    @Test
    void ambiguityIsRecordedEvenWhenTheSyncRetiredNoStaleDevices() {
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "UNKNOWN");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, false))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(9L, "device-guid")).thenReturn(
                List.of(IotDevice.builder().id(11L).build(), IotDevice.builder().id(12L).build()));

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", false);

        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("AMBIGUOUS");
        assertThat(enrollment.getDeviceId()).isNull();
    }

    @Test
    void anAmbiguousRowLinksOnceTheDuplicateDeviceHasBeenRetired() {
        // The recovery this whole path exists for: the stale row is gone, so the identifier now
        // resolves to exactly one device and the certificate stops being unmatched.
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "UNKNOWN");
        enrollment.setDeviceMatchStatus("AMBIGUOUS");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(9L, "device-guid"))
                .thenReturn(List.of(IotDevice.builder().id(12L).build()));
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isEqualTo(12L);
        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("MATCHED");
    }

    @Test
    void aStillAmbiguousRowIsNotRewrittenOnEverySync() {
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "UNKNOWN");
        enrollment.setDeviceMatchStatus("AMBIGUOUS");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true))
                .thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(9L, "device-guid")).thenReturn(
                List.of(IotDevice.builder().id(11L).build(), IotDevice.builder().id(12L).build()));

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("AMBIGUOUS");
        verify(enrollmentRepository, never()).save(enrollment);
        verifyNoInteractions(eventService);
    }

    @Test
    void aManagedDeviceIdRowRelinksOnlyViaTheStrictLookup() {
        // Relink must not be looser than ingestion: a MANAGED_DEVICE_ID row was resolved strictly
        // at issuance, so widening it here could make a link ingestion never would have made.
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "MANAGED_DEVICE_ID");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceDeviceId(9L, "device-guid"))
                .thenReturn(Optional.of(IotDevice.builder().id(11L).build()));
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isEqualTo(11L);
        verify(deviceRepository, never()).findRegisteredBySourceScopedIdentifier(any(), any());
    }

    /**
     * Two devices answering to one identifier is recorded and never linked. It is recorded rather
     * than left pending so the row leaves the half of the window reserved for enrollments still
     * waiting for their device — and it is no longer terminal, so the next sync that retires the
     * duplicate can still resolve it.
     */
    @Test
    void anAmbiguousIdentifierIsRecordedAndNeverLinked() {
        IotCertificateEnrollment enrollment = pending("MICROSOFT_VALIDATED", "UNKNOWN");
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of(enrollment));
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(9L, "device-guid")).thenReturn(
                List.of(IotDevice.builder().id(11L).build(), IotDevice.builder().id(12L).build()));

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        assertThat(enrollment.getDeviceId()).isNull();
        assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("AMBIGUOUS");
        verify(enrollmentRepository).save(enrollment);
        verify(eventService).recordEnrollment(eq(enrollment),
                eq(DeviceEventType.CERTIFICATE_DEVICE_UNMATCHED), eq("AMBIGUOUS"),
                any(), any(), any(), eq("scep-device-ambiguous:enr_1"), eq(NOW));
    }

    @Test
    void nothingPendingIsANoOp() {
        when(enrollmentRepository.findRelinkableByDeviceSourceId(9L, true)).thenReturn(List.of());

        service.relinkDevicesForSource(SOURCE, NOW, "corr-1", true);

        verify(deviceRepository, never()).findRegisteredBySourceScopedIdentifier(any(), any());
    }

}
