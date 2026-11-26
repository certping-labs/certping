// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.certmanagement.iot.dto.response.IdentityRegistrationResult;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.SyncMode;
import com.certmanagement.iot.enums.SyncStatus;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.iot.certificate.IotCertificateCorrelationService;
import com.certmanagement.iot.service.IotIdentityRegistrationService;
import com.certmanagement.iot.service.IotSyncOrchestrationService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.never;

@ExtendWith(MockitoExtension.class)
class IotIdentitySyncResponseHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    @Mock private IotIdentityRegistrationService registrationService;
    @Mock
    private IotCertificateCorrelationService certificateCorrelationService;
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceSyncStateRepository syncRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private IotSyncOrchestrationService orchestrationService;

    @Test
    void completionMayArriveBeforePartsAndDuplicatePartsRemainIdempotent() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        when(registrationService.upsertBatch(eq(42L), any(), any(), eq("correlation-1")))
                .thenReturn(new IdentityRegistrationResult("sync-1", 1, 0, 0, 0, List.of()));
        when(deviceRepository.countSeenInSync(10L, state.getStartedAt())).thenReturn(1L);
        Clock clock = Clock.fixed(Instant.parse("2026-08-24T10:05:00Z"), ZoneOffset.UTC);
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, clock);

        handler.handleComplete(completion());
        assertThat(state.getCompletionReceived()).isTrue();
        assertThat(state.getCompletedAt()).isNull();

        DeviceIdentitySyncResponsePart part = part();
        handler.handlePart(part);
        handler.handlePart(part);

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.OK);
        assertThat(state.getProcessedBatchCount()).isEqualTo(1);
        assertThat(state.getProcessedDeviceCount()).isEqualTo(1);
        assertThat(state.getCompletedAt()).isEqualTo(OffsetDateTime.parse("2026-08-24T10:05:00Z"));
        verify(registrationService, times(1)).upsertBatch(eq(42L), any(), any(), eq("correlation-1"));
        verify(registrationService).markOrphans(eq(source), any(), eq("correlation-1"));
    }

    @Test
    void sameBatchIndexWithDifferentChecksumFailsTheCurrentRun() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        state.setReceivedBatchesJson("{\"0\":\"checksum-from-earlier-payload\"}");
        state.setProcessedBatchCount(1);
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER,
                Clock.fixed(Instant.parse("2026-08-24T10:05:00Z"), ZoneOffset.UTC));

        handler.handlePart(part());

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.FAILED);
        assertThat(state.getLastError()).contains("different checksum");
        verify(registrationService, times(0)).upsertBatch(any(), any(), any(), any());
    }

    @Test
    void completionCountsLowerThanAcceptedDataFailTheRun() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        state.setProcessedDeviceCount(2);
        state.setProcessedBatchCount(1);
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER,
                Clock.fixed(Instant.parse("2026-08-24T10:05:00Z"), ZoneOffset.UTC));
        DeviceIdentitySyncResponseComplete completion = completion();
        completion.setTotalDevices(1);

        handler.handleComplete(completion);

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.FAILED);
        assertThat(state.getLastError()).contains("lower than");
    }

    @Test
    void perDeviceFailureCompletesAsPartialWithoutOrphaning() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        when(registrationService.upsertBatch(eq(42L), any(), any(), eq("correlation-1")))
                .thenReturn(new IdentityRegistrationResult("sync-1", 0, 0, 0, 1, List.of()));
        when(deviceRepository.countSeenInSync(10L, state.getStartedAt())).thenReturn(0L);
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER,
                Clock.fixed(Instant.parse("2026-08-24T10:05:00Z"), ZoneOffset.UTC));

        handler.handleComplete(completion());
        handler.handlePart(part());

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.PARTIAL);
        assertThat(state.getProcessedDeviceCount()).isZero();
        assertThat(state.getFailedDeviceCount()).isEqualTo(1);
        assertThat(state.getCompletedAt()).isNotNull();
        verify(registrationService, never()).markOrphans(any(), any(), any());
    }

    @Test
    void agentFailureNeverRunsOrphanDetection() {
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, Clock.systemUTC());

        handler.handleAgentError(
                "source-1", 42L, "sync-1", "PLATFORM_THROTTLED", "Graph throttled");

        verify(orchestrationService).markSyncFailed(
                "source-1", 42L, "sync-1", "PLATFORM_THROTTLED", "Graph throttled");
        verify(registrationService, never()).markOrphans(any(), any(), any());
    }

    @Test
    void responsePartArrivingAfterTerminalFailureIsIgnored() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState failed = runningState();
        failed.setSyncStatus(SyncStatus.PARTIAL);
        failed.setCompletedAt(OffsetDateTime.parse("2026-08-24T10:05:00Z"));
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(failed));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, Clock.systemUTC());

        handler.handlePart(part());

        verify(registrationService, never()).upsertBatch(any(), any(), any(), any());
        verify(registrationService, never()).markOrphans(any(), any(), any());
        verify(syncRepository, never()).save(any());
    }

    @Test
    void conflictingDuplicateCompletionFailsWithoutReplacingAcceptedCounts() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, Clock.systemUTC());
        DeviceIdentitySyncResponseComplete first = completion();
        first.setTotalDevices(2);
        first.setTotalBatches(2);
        handler.handleComplete(first);
        DeviceIdentitySyncResponseComplete conflicting = completion();

        handler.handleComplete(conflicting);

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.FAILED);
        assertThat(state.getExpectedDeviceCount()).isEqualTo(2);
        assertThat(state.getExpectedBatchCount()).isEqualTo(2);
        assertThat(state.getLastError()).contains("conflicting counts");
        verify(registrationService, never()).markOrphans(any(), any(), any());
    }

    @Test
    void deltaCompletionIsRejectedBeforeItCanTriggerOrphaning() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, Clock.systemUTC());
        DeviceIdentitySyncResponseComplete completion = completion();
        completion.setMode("DELTA");

        handler.handleComplete(completion);

        verify(syncRepository, never()).lockBySourceId(any());
        verify(registrationService, never()).markOrphans(any(), any(), any());
    }

    @Test
    void sparseBatchIndexesFailInsteadOfOrphaningMissingDevices() {
        IotDeviceSource source = source();
        IotDeviceSourceSyncState state = runningState();
        state.setCompletionReceived(true);
        state.setExpectedDeviceCount(2);
        state.setExpectedBatchCount(2);
        state.setProcessedDeviceCount(2);
        state.setProcessedBatchCount(2);
        state.setReceivedBatchesJson("{\"0\":\"a\",\"2\":\"b\"}");
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(syncRepository.lockBySourceId(10L)).thenReturn(Optional.of(state));
        IotIdentitySyncResponseHandler handler = new IotIdentitySyncResponseHandler(
                registrationService, certificateCorrelationService,
                deviceRepository, sourceRepository, syncRepository,
                eventService, orchestrationService, OBJECT_MAPPER, Clock.systemUTC());
        DeviceIdentitySyncResponseComplete complete = completion();
        complete.setTotalDevices(2);
        complete.setTotalBatches(2);

        handler.handleComplete(complete);

        assertThat(state.getSyncStatus()).isEqualTo(SyncStatus.FAILED);
        assertThat(state.getLastError()).contains("contiguous range");
        verify(registrationService, never()).markOrphans(any(), any(), any());
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary")
                .displayName("Primary Intune")
                .build();
    }

    private static IotDeviceSourceSyncState runningState() {
        return IotDeviceSourceSyncState.builder()
                .deviceSourceId(10L)
                .syncXref("sync-1")
                .syncStatus(SyncStatus.RUNNING)
                .syncMode(SyncMode.FULL)
                .requestedAt(OffsetDateTime.parse("2026-08-24T10:00:00Z"))
                .startedAt(OffsetDateTime.parse("2026-08-24T10:00:00Z"))
                .processedDeviceCount(0)
                .failedDeviceCount(0)
                .processedBatchCount(0)
                .receivedBatchesJson("{}")
                .completionReceived(false)
                .build();
    }

    private static DeviceIdentitySyncResponseComplete completion() {
        DeviceIdentitySyncResponseComplete completion = new DeviceIdentitySyncResponseComplete();
        completion.setOrganizationId("42");
        completion.setSourceXref("source-1");
        completion.setSyncXref("sync-1");
        completion.setMode("FULL");
        completion.setTotalDevices(1);
        completion.setTotalBatches(1);
        completion.setCorrelationId("correlation-1");
        return completion;
    }

    private static DeviceIdentitySyncResponsePart part() {
        DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto device =
                new DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto();
        device.setExternalId("device-1");
        device.setSerialNumber("SERIAL-1");
        DeviceIdentitySyncResponsePart part = new DeviceIdentitySyncResponsePart();
        part.setOrganizationId("42");
        part.setSourceXref("source-1");
        part.setSyncXref("sync-1");
        part.setBatchIndex(0);
        part.setDevices(List.of(device));
        part.setBatchChecksum(checksum(part.getDevices()));
        part.setRespondedAt("2026-08-24T10:04:00Z");
        part.setCorrelationId("correlation-1");
        return part;
    }

    private static String checksum(List<DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto> devices) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(OBJECT_MAPPER.writeValueAsBytes(devices)));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
