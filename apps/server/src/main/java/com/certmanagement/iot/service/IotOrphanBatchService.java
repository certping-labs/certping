// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.certificate.IotCertificateCorrelationService;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** Claims and orphans one bounded page so database locks are released between pages. */
@Service
@RequiredArgsConstructor
@Slf4j
class IotOrphanBatchService {
    static final int BATCH_SIZE = 500;

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceEventService eventService;
    private final IotCertificateCorrelationService certificateCorrelationService;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    int markNextBatch(
            Long sourceId, OffsetDateTime syncStartedAt, OffsetDateTime occurredAt,
            String correlationId) {
        List<IotDevice> staleDevices = deviceRepository.lockStaleDevices(
                sourceId, syncStartedAt, PageRequest.of(0, BATCH_SIZE));
        // Recorded before the rebind so the audit trail reads in causal order: the device went
        // stale, and that is why its certificates moved.
        staleDevices.forEach(device ->
                eventService.record(device, DeviceEventType.DEVICE_ORPHANED, ActorSource.SYNC,
                        null, Map.of("reason", "not returned by full sync"), correlationId));
        staleDevices.forEach(device -> device.setStatus(DeviceStatus.ORPHANED));
        deviceRepository.saveAll(staleDevices);
        int rebound = certificateCorrelationService.relinkFromOrphanedDevices(
                sourceId, syncStartedAt, staleDevices, occurredAt, correlationId);
        if (!staleDevices.isEmpty()) {
            log.info("Device orphan batch applied: sourceId={} count={} certificatesRebound={}",
                    sourceId, staleDevices.size(), rebound);
        }
        return staleDevices.size();
    }
}
