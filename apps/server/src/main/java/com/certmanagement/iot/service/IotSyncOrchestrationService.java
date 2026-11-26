// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.adapter.PlatformAdapterFactory;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.enums.SyncStatus;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.iot.profile.CertificateProfileSyncService;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import com.certmanagement.util.MdcIds;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotSyncOrchestrationService {
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceSyncStateRepository syncStateRepository;
    private final IotDeviceSourceEventService eventService;
    private final PlatformAdapterFactory adapterFactory;
    private final FeatureFlagService featureFlagService;
    private final IotSyncCommandDispatcher commandDispatcher;
    private final CertificateProfileSyncService certificateProfileSyncService;
    private final IotDeviceProperties properties;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    /** First manual sync enables hourly scheduling and dispatches a full sync immediately. */
    @Transactional
    public String startManualSync(Long organizationId, String sourceXref, Long actorUserId) {
        return dispatch(organizationId, sourceXref, actorUserId, true);
    }

    /** Called only by the server's scheduler for a source whose sync_enabled flag is already true. */
    @Transactional
    public String startScheduledSync(Long organizationId, String sourceXref) {
        return dispatch(organizationId, sourceXref, null, false);
    }

    @Transactional
    public void markSyncFailed(String sourceXref,
                               Long organizationId,
                               String syncXref,
                               String errorCode,
                               String detail) {
        if (sourceXref == null || organizationId == null || syncXref == null) {
            return;
        }
        sourceRepository.findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .ifPresent(source -> syncStateRepository.lockBySourceId(source.getId())
                        .filter(state -> syncXref.equals(state.getSyncXref())
                                && state.getCompletedAt() == null)
                        .ifPresent(state -> applyFailure(source, state, errorCode, detail)));
    }

    private String dispatch(Long organizationId,
                            String sourceXref,
                            Long actorUserId,
                            boolean enableSync) {
        IotDeviceSource source = sourceRepository
                .lockBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device source not found"));
        assertDispatchAllowed(source);

        OffsetDateTime now = OffsetDateTime.now(clock);
        IotDeviceSourceSyncState current = syncStateRepository.lockBySourceId(source.getId()).orElse(null);

        if (enableSync && !Boolean.TRUE.equals(source.getSyncEnabled())) {
            source.setSyncEnabled(true);
            sourceRepository.save(source);
            eventService.record(source, DeviceSourceEventType.SYNC_ENABLED, "ENABLED",
                    Map.of("actorUserId", actorUserId), now, MdcIds.correlationId(),
                    "sync-enabled:" + now.toInstant());
        }

        if (current != null && current.getSyncStatus() == SyncStatus.PENDING
                && current.getCompletedAt() == null) {
            dispatchAfterCommit(source.getId(), current.getSyncXref());
            if (enableSync) {
                certificateProfileSyncService.requestInitialIfNeeded(source.getId(), actorUserId);
                iotAudit.syncStarted(source, current.getSyncXref());
            }
            return current.getSyncXref();
        }
        assertNotInProgress(current, now);

        String syncXref = xref("sync_");
        IotDeviceSourceSyncState state = current == null
                ? new IotDeviceSourceSyncState()
                : current;
        resetState(state, source.getId(), syncXref, actorUserId, now);
        syncStateRepository.save(state);

        eventService.record(source, DeviceSourceEventType.SYNC_REQUESTED, SyncStatus.PENDING.name(),
                Map.of("syncXref", syncXref, "manual", enableSync), now,
                MdcIds.correlationId(), syncXref + ":requested");
        dispatchAfterCommit(source.getId(), syncXref);
        if (enableSync) {
            certificateProfileSyncService.requestInitialIfNeeded(source.getId(), actorUserId);
            // A member's sync; the hourly scheduled syncs are CertPing's routine and leave no row.
            iotAudit.syncStarted(source, syncXref);
        }
        log.info("IoT source sync prepared: source={} org={} sync={}",
                sourceXref, organizationId, syncXref);
        return syncXref;
    }

    private void assertDispatchAllowed(IotDeviceSource source) {
        if (source.getStatus() != DeviceSourceStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Device source must be ACTIVE");
        }
        if (!adapterFactory.isSupported(source.getProvider())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No CMS adapter is available for " + source.getProvider());
        }
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, source.getOrganizationId())) {
            throw new ResponseStatusException(HttpStatus.LOCKED, "IoT device management is disabled");
        }
        String providerFlag = providerFeatureFlag(source.getProvider());
        if (providerFlag != null
                && !featureFlagService.isEnabled(providerFlag, source.getOrganizationId())) {
            throw new ResponseStatusException(HttpStatus.LOCKED,
                    source.getProvider() + " integration is disabled");
        }
    }

    private static String providerFeatureFlag(DeviceSourceProvider provider) {
        return provider == DeviceSourceProvider.INTUNE ? FeatureFlags.IOT_PROVIDER_INTUNE : null;
    }

    private void assertNotInProgress(IotDeviceSourceSyncState state, OffsetDateTime now) {
        if (state == null || state.getCompletedAt() != null) {
            return;
        }
        OffsetDateTime staleBefore = now.minus(properties.getRunningSyncTimeout());
        if (state.getRequestedAt() == null || !state.getRequestedAt().isBefore(staleBefore)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "sync already in progress");
        }
    }

    private static void resetState(IotDeviceSourceSyncState state,
                                   Long sourceId,
                                   String syncXref,
                                   Long actorUserId,
                                   OffsetDateTime now) {
        state.setDeviceSourceId(sourceId);
        state.setSyncXref(syncXref);
        state.setSyncStatus(SyncStatus.PENDING);
        state.setSyncMode(com.certmanagement.iot.enums.SyncMode.FULL);
        state.setRequestedByUserId(actorUserId);
        state.setRequestedAt(now);
        state.setStartedAt(null);
        state.setCompletedAt(null);
        state.setExpectedDeviceCount(null);
        state.setProcessedDeviceCount(0);
        state.setFailedDeviceCount(0);
        state.setExpectedBatchCount(null);
        state.setProcessedBatchCount(0);
        state.setReceivedBatchesJson("{}");
        state.setCompletionReceived(false);
        state.setLastError(null);
        state.setUpdatedAt(now);
    }

    private void applyFailure(IotDeviceSource source,
                              IotDeviceSourceSyncState state,
                              String errorCode,
                              String detail) {
        int processed = state.getProcessedDeviceCount() == null ? 0 : state.getProcessedDeviceCount();
        SyncStatus status = processed > 0 ? SyncStatus.PARTIAL : SyncStatus.FAILED;
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setSyncStatus(status);
        state.setCompletedAt(now);
        state.setLastError(truncate(formatError(errorCode, detail), 1000));
        state.setUpdatedAt(now);
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_FAILED, status.name(),
                Map.of("syncXref", state.getSyncXref(), "processedDeviceCount", processed),
                now, null, state.getSyncXref() + ":failed");
    }

    private static String formatError(String code, String detail) {
        if (code == null || code.isBlank()) {
            return detail == null || detail.isBlank() ? "unknown error" : detail;
        }
        return detail == null || detail.isBlank() ? code : code + ": " + detail;
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }

    private void dispatchAfterCommit(Long sourceId, String syncXref) {
        Runnable publish = () -> {
            try {
                commandDispatcher.publishPending(sourceId, syncXref);
            } catch (Exception exception) {
                log.warn("IoT sync remains PENDING after publish failure: sourceId={} sync={} reason={}",
                        sourceId, syncXref, exception.getMessage());
            }
        };
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            publish.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                publish.run();
            }
        });
    }
}
