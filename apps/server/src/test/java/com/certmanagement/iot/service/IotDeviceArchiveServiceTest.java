// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceArchiveServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);
    private static final long ORG = 42L;
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-09-01T14:00:00Z");

    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private FeatureFlagService featureFlagService;
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-01T14:00:00Z"), ZoneOffset.UTC);

    private IotDeviceArchiveService service() {
        return new IotDeviceArchiveService(deviceRepository, certificateRepository,
                eventService, featureFlagService, clock, iotAudit);
    }

    private IotDevice device(DeviceStatus status, boolean archived) {
        return IotDevice.builder().id(7L).deviceXref("dev_1").organizationId(ORG)
                .status(status).isDeleted(archived).build();
    }

    private void stubLock(IotDevice device) {
        lenient().when(deviceRepository.lockByDeviceXrefForArchive("dev_1", ORG))
                .thenReturn(Optional.of(device));
        lenient().when(deviceRepository.lockByDeviceXrefForRestore("dev_1", ORG))
                .thenReturn(Optional.of(device));
    }

    @Test
    void anOrphanedDeviceWithNothingUsableLeftIsHiddenButKept() {
        IotDevice device = device(DeviceStatus.ORPHANED, false);
        stubLock(device);
        when(certificateRepository.countUsableForDevice(7L, NOW)).thenReturn(0L);

        service().archive(ORG, "dev_1", 5L);

        assertThat(device.getIsDeleted()).isTrue();
        // Hidden, not deleted: the status that explains why it is gone is left intact.
        assertThat(device.getStatus()).isEqualTo(DeviceStatus.ORPHANED);
        verify(deviceRepository).save(device);
        verify(deviceRepository, never()).delete(any());
        verify(eventService).record(eq(device), eq(DeviceEventType.DEVICE_ARCHIVED),
                eq(ActorSource.UI), eq(5L), any(), eq(null));
        verify(iotAudit).deviceArchived(device);
    }

    @Test
    void bothPathsAreGatedOnTheIotFeatureFlag() {
        doThrow(new ResponseStatusException(HttpStatus.FORBIDDEN, "disabled"))
                .when(featureFlagService)
                .assertEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, ORG);

        assertThatThrownBy(() -> service().archive(ORG, "dev_1", 5L))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> service().restore(ORG, "dev_1", 5L))
                .isInstanceOf(ResponseStatusException.class);

        verifyNoInteractions(deviceRepository, certificateRepository, eventService);
    }

    @Test
    void aDeviceTheSourceStillReportsCannotBeArchived() {
        stubLock(device(DeviceStatus.REGISTERED, false));

        assertThatThrownBy(() -> service().archive(ORG, "dev_1", 5L))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("no longer reports");

        verify(deviceRepository, never()).save(any());
        verifyNoInteractions(certificateRepository, eventService);
    }

    /** Hiding a device that still holds a trusted certificate would hide a live credential. */
    @Test
    void aDeviceStillHoldingAUsableCertificateCannotBeArchived() {
        stubLock(device(DeviceStatus.ORPHANED, false));
        when(certificateRepository.countUsableForDevice(7L, NOW)).thenReturn(2L);

        assertThatThrownBy(() -> service().archive(ORG, "dev_1", 5L))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("2 certificate(s)");

        verify(deviceRepository, never()).save(any());
        verifyNoInteractions(eventService);
    }

    @Test
    void archivingAnAlreadyArchivedDeviceChangesNothing() {
        stubLock(device(DeviceStatus.ORPHANED, true));

        service().archive(ORG, "dev_1", 5L);

        verify(deviceRepository, never()).save(any());
        verifyNoInteractions(certificateRepository, eventService);
    }

    @Test
    void restoringPutsTheDeviceBackInTheInventory() {
        IotDevice device = device(DeviceStatus.ORPHANED, true);
        stubLock(device);

        service().restore(ORG, "dev_1", 5L);

        assertThat(device.getIsDeleted()).isFalse();
        verify(deviceRepository).save(device);
        verify(eventService).record(eq(device), eq(DeviceEventType.DEVICE_RESTORED),
                eq(ActorSource.UI), eq(5L), any(), eq(null));
        verify(iotAudit).deviceRestored(device);
    }

    @Test
    void restoringADeviceThatIsNotArchivedChangesNothing() {
        stubLock(device(DeviceStatus.ORPHANED, false));

        service().restore(ORG, "dev_1", 5L);

        verify(deviceRepository, never()).save(any());
        verifyNoInteractions(eventService);
    }
}
