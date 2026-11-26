// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.certificate.IotCertificateCorrelationService;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotOrphanBatchServiceTest {
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private IotCertificateCorrelationService certificateCorrelationService;

    @Test
    void locksAndUpdatesAtMostOneConfiguredPage() {
        OffsetDateTime syncStartedAt = OffsetDateTime.parse("2026-09-01T09:00:00Z");
        IotDevice first = IotDevice.builder().id(1L).status(DeviceStatus.REGISTERED).build();
        IotDevice second = IotDevice.builder().id(2L).status(DeviceStatus.REGISTERED).build();
        when(deviceRepository.lockStaleDevices(
                10L, syncStartedAt, PageRequest.of(0, IotOrphanBatchService.BATCH_SIZE)))
                .thenReturn(List.of(first, second));

        OffsetDateTime occurredAt = OffsetDateTime.parse("2026-09-01T09:05:00Z");

        int updated = new IotOrphanBatchService(
                deviceRepository, eventService, certificateCorrelationService)
                .markNextBatch(10L, syncStartedAt, occurredAt, "corr-1");

        assertThat(updated).isEqualTo(2);
        assertThat(List.of(first.getStatus(), second.getStatus()))
                .containsOnly(DeviceStatus.ORPHANED);
        verify(deviceRepository).saveAll(List.of(first, second));
        // The exact page it just orphaned, and nothing wider: that bound is the whole design.
        verify(certificateCorrelationService).relinkFromOrphanedDevices(
                10L, syncStartedAt, List.of(first, second), occurredAt, "corr-1");
        verify(eventService, times(2)).record(any(), eq(DeviceEventType.DEVICE_ORPHANED),
                eq(ActorSource.SYNC), eq(null), any(), eq("corr-1"));
    }
}
