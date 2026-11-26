// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.SyncMode;
import com.certmanagement.iot.enums.SyncStatus;
import com.certmanagement.iot.messaging.DeviceIdentitySyncCommand;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.service.OrgTypeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;

/** Publishes an already committed PENDING sync and records the RUNNING transition. */
@Slf4j
@Service
@RequiredArgsConstructor
class IotSyncCommandDispatcher {
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceSyncStateRepository syncStateRepository;
    private final IotDeviceSourceEventService eventService;
    private final OrgTypeResolver orgTypeResolver;
    private final CertAgentPublisher certAgentPublisher;
    private final Clock clock;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void publishPending(Long sourceId, String expectedSyncXref) {
        IotDeviceSource source = sourceRepository.findById(sourceId).orElse(null);
        IotDeviceSourceSyncState state = syncStateRepository.lockBySourceId(sourceId).orElse(null);
        if (source == null || state == null || state.getSyncStatus() != SyncStatus.PENDING
                || !expectedSyncXref.equals(state.getSyncXref())) {
            return;
        }

        DeviceIdentitySyncCommand command = DeviceIdentitySyncCommand.builder()
                .requestId(state.getSyncXref())
                .correlationId(state.getSyncXref())
                .organizationId(String.valueOf(source.getOrganizationId()))
                .orgType(orgTypeResolver.resolve(source.getOrganizationId()))
                .sourceXref(source.getSourceXref())
                .connectionProfileRef(source.getConnectionProfileRef())
                .provider(source.getProvider().name())
                .syncXref(state.getSyncXref())
                .mode(SyncMode.FULL.name())
                .requestedAt(state.getRequestedAt().toString())
                .build();

        certAgentPublisher.publishDeviceIdentitySyncCommand(command);

        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setSyncStatus(SyncStatus.RUNNING);
        state.setStartedAt(now);
        state.setUpdatedAt(now);
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_STARTED, SyncStatus.RUNNING.name(),
                Map.of("syncXref", state.getSyncXref()), now, command.getCorrelationId(),
                state.getSyncXref() + ":started");
        log.info("IoT source sync published: source={} org={} sync={}",
                source.getSourceXref(), source.getOrganizationId(), state.getSyncXref());
    }
}
