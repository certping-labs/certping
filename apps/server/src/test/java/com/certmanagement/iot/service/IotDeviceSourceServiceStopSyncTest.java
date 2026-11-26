// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.service.audit.IotAuditRecorder;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Stopping a source's scheduled sync is recorded once, when it was on; stopping it again records nothing. */
class IotDeviceSourceServiceStopSyncTest {

    private final IotDeviceSourceRepository sourceRepository = mock(IotDeviceSourceRepository.class);
    private final IotDeviceSourceHealthStatusRepository healthRepository = mock(IotDeviceSourceHealthStatusRepository.class);
    private final IotDeviceSourceSyncStateRepository syncRepository = mock(IotDeviceSourceSyncStateRepository.class);
    private final IotDeviceRepository deviceRepository = mock(IotDeviceRepository.class);
    private final IotDeviceSourceEventService eventService = mock(IotDeviceSourceEventService.class);
    private final IotAuditRecorder iotAudit = mock(IotAuditRecorder.class);
    private final IotDeviceSourceService service = new IotDeviceSourceService(sourceRepository, healthRepository,
            syncRepository, deviceRepository, eventService, new IotDeviceProperties(), JsonMapper.builderWithJackson2Defaults().build(),
            Clock.fixed(Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC), iotAudit);

    @Test
    void stoppingAnEnabledSyncIsRecorded() {
        IotDeviceSource source = source(true);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L)).thenReturn(Optional.of(source));
        when(healthRepository.findById(10L)).thenReturn(Optional.empty());
        when(syncRepository.findById(10L)).thenReturn(Optional.empty());
        when(deviceRepository.countByDeviceSourceIdAndIsDeletedFalse(anyLong())).thenReturn(0L);

        service.stopSync(42L, "source-1", 7L);

        assertThat(source.getSyncEnabled()).isFalse();
        verify(iotAudit).syncStopped(source);
    }

    @Test
    void stoppingAStoppedSyncRecordsNothing() {
        IotDeviceSource source = source(false);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L)).thenReturn(Optional.of(source));
        when(healthRepository.findById(any())).thenReturn(Optional.empty());
        when(syncRepository.findById(any())).thenReturn(Optional.empty());

        service.stopSync(42L, "source-1", 7L);

        verifyNoInteractions(iotAudit);
    }

    private static IotDeviceSource source(boolean syncEnabled) {
        return IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary")
                .displayName("Primary")
                .syncEnabled(syncEnabled)
                .status(DeviceSourceStatus.ACTIVE)
                .build();
    }
}
