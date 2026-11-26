// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceConnectedThingRepository;
import com.certmanagement.iot.repository.IotDeviceEndpointPostureRepository;
import com.certmanagement.iot.repository.IotDeviceOwnerRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceQueryServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);

    @Mock
    private IotDeviceRepository deviceRepository;
    @Mock
    private IotDeviceSourceRepository sourceRepository;
    @Mock
    private IotDeviceSourceSyncStateRepository syncStateRepository;
    @Mock
    private IotDeviceOwnerRepository ownerRepository;
    @Mock
    private IotDeviceEndpointPostureRepository postureRepository;
    @Mock
    private IotDeviceConnectedThingRepository connectedThingRepository;
    @Mock
    private IotDeviceSourceHealthStatusRepository healthRepository;
    @Mock
    private IotDeviceEventService eventService;

    private IotDeviceQueryService service;

    @BeforeEach
    void setUp() {
        service = new IotDeviceQueryService(
                deviceRepository, sourceRepository, syncStateRepository, ownerRepository,
                postureRepository, connectedThingRepository, healthRepository, eventService,
                new IotDeviceProperties(), JsonMapper.builderWithJackson2Defaults().build(),
                Clock.fixed(Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC), iotAudit);
    }

    @Test
    void listRejectsUnknownSourceInsteadOfRemovingTheFilter() {
        long organizationId = 42L;
        String sourceXref = "src_unknown";
        when(sourceRepository.findBySourceXrefAndOrganizationId(sourceXref, organizationId))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.list(
                organizationId, sourceXref, null, null, null, null, Pageable.unpaged()))
                .isInstanceOfSatisfying(ResponseStatusException.class, exception -> {
                    assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(exception.getReason()).isEqualTo("Device source not found");
                });

        verify(sourceRepository).findBySourceXrefAndOrganizationId(sourceXref, organizationId);
        verifyNoInteractions(deviceRepository, ownerRepository, postureRepository);
    }

    @Test
    void decommissionRecordsTheStatusTransitionWithoutPii() {
        IotDevice device = IotDevice.builder()
                .id(7L)
                .organizationId(42L)
                .deviceXref("dev_1")
                .deviceSourceId(10L)
                .status(DeviceStatus.REGISTERED)
                .build();
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary")
                .displayName("Primary")
                .syncEnabled(true)
                .status(DeviceSourceStatus.ACTIVE)
                .build();
        when(deviceRepository.lockByDeviceXrefAndOrganizationId("dev_1", 42L))
                .thenReturn(Optional.of(device));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source));
        when(postureRepository.findByDeviceId(7L)).thenReturn(Optional.empty());
        when(connectedThingRepository.findByDeviceId(7L)).thenReturn(Optional.empty());
        when(ownerRepository.findByDeviceIdAndIsDeletedFalse(7L)).thenReturn(Optional.empty());

        service.decommission(42L, "dev_1", 9L);

        assertThat(device.getStatus()).isEqualTo(DeviceStatus.DECOMMISSIONED);
        assertThat(device.getDecommissionedAt()).isNotNull();
        verify(eventService).record(
                device, DeviceEventType.DECOMMISSIONED, ActorSource.UI, 9L,
                java.util.Map.of(
                        "previousStatus", "REGISTERED",
                        "newStatus", "DECOMMISSIONED"),
                null);
        verify(iotAudit).deviceDecommissioned(device, DeviceStatus.REGISTERED);
    }
}
