// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.adapter.PlatformAdapterFactory;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.enums.SyncStatus;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotSyncOrchestrationServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceSyncStateRepository syncRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private PlatformAdapterFactory adapterFactory;
    @Mock private FeatureFlagService featureFlagService;
    @Mock private IotSyncCommandDispatcher commandDispatcher;
    @Mock private com.certmanagement.iot.profile.CertificateProfileSyncService profileSyncService;

    @Test
    void firstManualSyncEnablesSchedulingAndPublishesASecretFreeProfileCommand() {
        IotDeviceSource source = source();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.empty());
        when(adapterFactory.isSupported(DeviceSourceProvider.INTUNE)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_PROVIDER_INTUNE, 42L)).thenReturn(true);
        Clock clock = Clock.fixed(Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC);
        IotSyncOrchestrationService service = new IotSyncOrchestrationService(
                sourceRepository, syncRepository, eventService, adapterFactory,
                featureFlagService, commandDispatcher, profileSyncService,
                new IotDeviceProperties(), clock, iotAudit);

        String syncXref = service.startManualSync(42L, "source-1", 7L);

        assertThat(source.getSyncEnabled()).isTrue();
        assertThat(syncXref).startsWith("sync_");
        verify(commandDispatcher).publishPending(10L, syncXref);
        verify(profileSyncService).requestInitialIfNeeded(10L, 7L);
        verify(sourceRepository).save(source);
        verify(iotAudit).syncStarted(source, syncXref);
    }

    @Test
    void lateAgentErrorCannotOverwriteAnAlreadyCompletedRun() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState completed = IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-1")
                .syncStatus(SyncStatus.OK)
                .completedAt(OffsetDateTime.parse("2026-08-24T10:00:00Z"))
                .build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(completed));
        IotSyncOrchestrationService service = new IotSyncOrchestrationService(
                sourceRepository, syncRepository, eventService, adapterFactory,
                featureFlagService, commandDispatcher, profileSyncService,
                new IotDeviceProperties(), Clock.systemUTC(), iotAudit);

        service.markSyncFailed("source-1", 42L, "sync-1", "LATE_ERROR", "late");

        verify(syncRepository, never()).save(completed);
    }

    @Test
    void agentErrorAfterSomeDevicesMarksRunPartial() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState running = IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-1")
                .syncStatus(SyncStatus.RUNNING)
                .requestedAt(OffsetDateTime.parse("2026-08-24T09:59:00Z"))
                .startedAt(OffsetDateTime.parse("2026-08-24T10:00:00Z"))
                .processedDeviceCount(20)
                .failedDeviceCount(0)
                .processedBatchCount(1)
                .completedAt(null)
                .build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(running));
        IotSyncOrchestrationService service = serviceAt("2026-08-24T10:05:00Z");

        service.markSyncFailed(
                "source-1", 42L, "sync-1", "PLATFORM_THROTTLED", "Graph throttled");

        assertThat(running.getSyncStatus()).isEqualTo(SyncStatus.PARTIAL);
        assertThat(running.getProcessedDeviceCount()).isEqualTo(20);
        assertThat(running.getCompletedAt())
                .isEqualTo(OffsetDateTime.parse("2026-08-24T10:05:00Z"));
        assertThat(running.getLastError()).isEqualTo("PLATFORM_THROTTLED: Graph throttled");
        verify(syncRepository).save(running);
        verify(eventService).record(
                source,
                DeviceSourceEventType.SYNC_FAILED,
                SyncStatus.PARTIAL.name(),
                Map.of("syncXref", "sync-1", "processedDeviceCount", 20),
                OffsetDateTime.parse("2026-08-24T10:05:00Z"),
                null,
                "sync-1:failed");
    }

    @Test
    void agentErrorBeforeAnyDeviceMarksRunFailed() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState running = IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-1")
                .syncStatus(SyncStatus.RUNNING)
                .requestedAt(OffsetDateTime.parse("2026-08-24T09:59:00Z"))
                .startedAt(OffsetDateTime.parse("2026-08-24T10:00:00Z"))
                .processedDeviceCount(0)
                .failedDeviceCount(0)
                .processedBatchCount(0)
                .completedAt(null)
                .build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(running));
        IotSyncOrchestrationService service = serviceAt("2026-08-24T10:05:00Z");

        service.markSyncFailed(
                "source-1", 42L, "sync-1", "PLATFORM_THROTTLED", "Graph throttled");

        assertThat(running.getSyncStatus()).isEqualTo(SyncStatus.FAILED);
        assertThat(running.getCompletedAt())
                .isEqualTo(OffsetDateTime.parse("2026-08-24T10:05:00Z"));
        verify(syncRepository).save(running);
        verify(eventService).record(
                source,
                DeviceSourceEventType.SYNC_FAILED,
                SyncStatus.FAILED.name(),
                Map.of("syncXref", "sync-1", "processedDeviceCount", 0),
                OffsetDateTime.parse("2026-08-24T10:05:00Z"),
                null,
                "sync-1:failed");
    }

    @Test
    void manualStartReEnablesAStoppedSourceWithPendingWork() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState pending = IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-pending")
                .syncStatus(SyncStatus.PENDING)
                .requestedAt(OffsetDateTime.parse("2026-08-24T09:59:00Z"))
                .build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(pending));
        allowDispatch();
        IotSyncOrchestrationService service = serviceAt("2026-08-24T10:00:00Z");

        String syncXref = service.startManualSync(42L, "source-1", 7L);

        assertThat(syncXref).isEqualTo("sync-pending");
        assertThat(source.getSyncEnabled()).isTrue();
        verify(sourceRepository).save(source);
        verify(commandDispatcher).publishPending(10L, "sync-pending");
    }

    @Test
    void unfinishedPartialStateStillBlocksASecondManualRun() {
        IotDeviceSource source = source();
        source.setSyncEnabled(true);
        IotDeviceSourceSyncState unfinished = IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-active")
                .syncStatus(SyncStatus.PARTIAL)
                .requestedAt(OffsetDateTime.parse("2026-08-24T09:59:00Z"))
                .completedAt(null)
                .build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(unfinished));
        allowDispatch();
        IotSyncOrchestrationService service = serviceAt("2026-08-24T10:00:00Z");

        assertThatThrownBy(() -> service.startManualSync(42L, "source-1", 7L))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("sync already in progress");
        verify(commandDispatcher, never()).publishPending(any(), any());
    }

    private void allowDispatch() {
        when(adapterFactory.isSupported(DeviceSourceProvider.INTUNE)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_PROVIDER_INTUNE, 42L)).thenReturn(true);
    }

    private IotSyncOrchestrationService serviceAt(String instant) {
        return new IotSyncOrchestrationService(
                sourceRepository, syncRepository, eventService, adapterFactory,
                featureFlagService, commandDispatcher, profileSyncService,
                new IotDeviceProperties(),
                Clock.fixed(Instant.parse(instant), ZoneOffset.UTC), iotAudit);
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder()
                .id(10L)
                .sourceXref("source-1")
                .organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary")
                .displayName("Primary Intune")
                .syncEnabled(false)
                .status(DeviceSourceStatus.ACTIVE)
                .firstAdvertisedAt(OffsetDateTime.parse("2026-08-24T09:00:00Z"))
                .lastAdvertisedAt(OffsetDateTime.parse("2026-08-24T09:00:00Z"))
                .build();
    }
}
