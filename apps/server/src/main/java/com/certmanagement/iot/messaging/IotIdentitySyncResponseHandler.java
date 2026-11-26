// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.dto.request.IdentityRegistrationRequest;
import com.certmanagement.iot.dto.response.IdentityRegistrationResult;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.SyncMode;
import com.certmanagement.iot.enums.SyncStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.iot.service.IotIdentityRegistrationService;
import com.certmanagement.iot.service.IotSyncOrchestrationService;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Applies sync messages only when their server-issued sync_xref still owns the source. */
@Slf4j
@Component
@RequiredArgsConstructor
public class IotIdentitySyncResponseHandler {
    private static final int MAX_DEVICES_PER_BATCH = 1_000;
    private static final int MAX_TOTAL_DEVICES = 10_000_000;
    private static final int MAX_TOTAL_BATCHES = 1_000_000;

    private final IotIdentityRegistrationService registrationService;
    private final com.certmanagement.iot.certificate.IotCertificateCorrelationService
            certificateCorrelationService;
    private final IotDeviceRepository deviceRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceSyncStateRepository syncStateRepository;
    private final IotDeviceSourceEventService eventService;
    private final IotSyncOrchestrationService orchestrationService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Transactional
    public void handlePart(DeviceIdentitySyncResponsePart part) {
        Long organizationId = parseOrgId(part.getOrganizationId());
        IotDeviceSource source = findSource(organizationId, part.getSourceXref());
        if (source == null || part.getSyncXref() == null || part.getBatchIndex() < 0
                || part.getBatchIndex() >= MAX_TOTAL_BATCHES
                || part.getBatchChecksum() == null || part.getBatchChecksum().isBlank()
                || part.getDevices() == null || part.getDevices().size() > MAX_DEVICES_PER_BATCH) {
            log.warn("Dropping invalid device-source sync part: source={} sync={} batch={}",
                    part.getSourceXref(), part.getSyncXref(), part.getBatchIndex());
            return;
        }

        IotDeviceSourceSyncState state = syncStateRepository.lockBySourceId(source.getId()).orElse(null);
        if (!ownsCurrentSync(state, part.getSyncXref())) {
            log.info("Ignoring stale sync part: source={} sync={} current={}",
                    source.getSourceXref(), part.getSyncXref(),
                    state == null ? null : state.getSyncXref());
            return;
        }
        ensureStarted(source, state, part.getCorrelationId());

        String computedChecksum = checksum(part.getDevices());
        if (!MessageDigest.isEqual(
                computedChecksum.getBytes(StandardCharsets.US_ASCII),
                part.getBatchChecksum().getBytes(StandardCharsets.US_ASCII))) {
            failInvalidPayload(source, state, part.getCorrelationId(), "CHECKSUM_MISMATCH",
                    "Batch checksum does not match the received device payload");
            return;
        }

        Map<String, String> receivedBatches = readBatches(state.getReceivedBatchesJson());
        String batchKey = String.valueOf(part.getBatchIndex());
        String previousChecksum = receivedBatches.get(batchKey);
        if (previousChecksum != null) {
            if (!previousChecksum.equals(part.getBatchChecksum())) {
                failChecksumConflict(source, state, part.getBatchIndex());
            }
            return;
        }

        List<DeviceIdentityPayload> devices = toPayloads(part.getDevices());
        IdentityRegistrationResult result = registrationService.upsertBatch(
                organizationId,
                new IdentityRegistrationRequest(source.getSourceXref(), part.getSyncXref(), devices),
                ActorSource.AGENT,
                part.getCorrelationId());

        int applied = result.created() + result.updated() + result.unchanged();
        receivedBatches.put(batchKey, part.getBatchChecksum());
        state.setReceivedBatchesJson(writeBatches(receivedBatches));
        state.setProcessedBatchCount(receivedBatches.size());
        state.setProcessedDeviceCount(state.getProcessedDeviceCount() + applied);
        state.setFailedDeviceCount(state.getFailedDeviceCount() + result.failed());
        if (result.failed() > 0) {
            state.setLastError(result.failed() + " device(s) could not be ingested");
        }
        log.info("Device sync part applied: source={} sync={} batch={} received={} applied={} "
                        + "created={} updated={} unchanged={} failed={} correlation={}",
                source.getSourceXref(), part.getSyncXref(), part.getBatchIndex(), devices.size(),
                applied, result.created(), result.updated(), result.unchanged(), result.failed(),
                part.getCorrelationId());
        state.setUpdatedAt(OffsetDateTime.now(clock));
        syncStateRepository.save(state);

        eventService.record(source, DeviceSourceEventType.SYNC_PART_RECEIVED,
                result.failed() == 0 ? "APPLIED" : SyncStatus.PARTIAL.name(),
                Map.of("syncXref", part.getSyncXref(), "batchIndex", part.getBatchIndex(),
                        "deviceCount", devices.size(), "failedDeviceCount", result.failed()),
                parseTimestamp(part.getRespondedAt()), part.getCorrelationId(),
                part.getSyncXref() + ":part:" + part.getBatchIndex());
        finalizeIfComplete(source, state, part.getCorrelationId());
    }

    @Transactional
    public void handleComplete(DeviceIdentitySyncResponseComplete complete) {
        Long organizationId = parseOrgId(complete.getOrganizationId());
        IotDeviceSource source = findSource(organizationId, complete.getSourceXref());
        if (source == null || complete.getSyncXref() == null
                || !SyncMode.FULL.name().equalsIgnoreCase(complete.getMode())
                || complete.getTotalDevices() < 0 || complete.getTotalDevices() > MAX_TOTAL_DEVICES
                || complete.getTotalBatches() < 0 || complete.getTotalBatches() > MAX_TOTAL_BATCHES
                || (complete.getTotalDevices() == 0) != (complete.getTotalBatches() == 0)) {
            log.warn("Dropping invalid device-source sync completion: source={} sync={}",
                    complete.getSourceXref(), complete.getSyncXref());
            return;
        }
        IotDeviceSourceSyncState state = syncStateRepository.lockBySourceId(source.getId()).orElse(null);
        if (!ownsCurrentSync(state, complete.getSyncXref())) {
            log.info("Ignoring stale sync completion: source={} sync={} current={}",
                    source.getSourceXref(), complete.getSyncXref(),
                    state == null ? null : state.getSyncXref());
            return;
        }
        ensureStarted(source, state, complete.getCorrelationId());
        if (Boolean.TRUE.equals(state.getCompletionReceived())) {
            if (!completionCountsMatch(state, complete)) {
                failInvalidPayload(source, state, complete.getCorrelationId(),
                        "COMPLETION_CONFLICT",
                        "Sync completion was redelivered with conflicting counts");
                return;
            }
            finalizeIfComplete(source, state, complete.getCorrelationId());
            return;
        }
        state.setExpectedDeviceCount(complete.getTotalDevices());
        state.setExpectedBatchCount(complete.getTotalBatches());
        state.setCompletionReceived(true);
        state.setUpdatedAt(OffsetDateTime.now(clock));
        syncStateRepository.save(state);
        finalizeIfComplete(source, state, complete.getCorrelationId());
    }

    @Transactional
    public void handleAgentError(String sourceXref,
                                 Long organizationId,
                                 String syncXref,
                                 String errorCode,
                                 String detail) {
        orchestrationService.markSyncFailed(
                sourceXref, organizationId, syncXref, errorCode, detail);
    }

    private void finalizeIfComplete(IotDeviceSource source,
                                    IotDeviceSourceSyncState state,
                                    String correlationId) {
        if (!Boolean.TRUE.equals(state.getCompletionReceived())
                || state.getExpectedBatchCount() == null) {
            return;
        }
        int accountedDevices = state.getProcessedDeviceCount() + state.getFailedDeviceCount();
        if (state.getExpectedDeviceCount() == null) {
            return;
        }
        if (state.getProcessedBatchCount() > state.getExpectedBatchCount()
                || accountedDevices > state.getExpectedDeviceCount()) {
            failCountMismatch(source, state, correlationId, accountedDevices);
            return;
        }
        if (state.getProcessedBatchCount() < state.getExpectedBatchCount()
                || accountedDevices < state.getExpectedDeviceCount()) {
            return;
        }

        Map<String, String> receivedBatches = readBatches(state.getReceivedBatchesJson());
        if (!hasExactBatchRange(receivedBatches, state.getExpectedBatchCount())) {
            failInvalidPayload(source, state, correlationId, "NON_CONTIGUOUS_BATCHES",
                    "Accepted batch indexes do not match the expected contiguous range");
            return;
        }
        long distinctDevices = state.getStartedAt() == null ? -1
                : deviceRepository.countSeenInSync(source.getId(), state.getStartedAt());
        if (distinctDevices != state.getProcessedDeviceCount()) {
            failInvalidPayload(source, state, correlationId, "DISTINCT_DEVICE_COUNT_MISMATCH",
                    "Distinct devices seen in the run do not match successfully processed devices");
            return;
        }

        boolean partial = state.getFailedDeviceCount() > 0;
        // Only a complete run may retire the devices it did not see. This also decides whether a
        // certificate matching two device rows is a real verdict or just a duplicate row that has
        // not been orphaned yet.
        boolean staleDevicesRetired = !partial && state.getStartedAt() != null;
        if (staleDevicesRetired) {
            registrationService.markOrphans(source, state.getStartedAt(), correlationId);
        }
        OffsetDateTime completedAt = OffsetDateTime.now(clock);
        // Devices that just arrived may be the ones pending certificate enrollments were waiting
        // for; a partial sync still adds devices, so re-link on both outcomes.
        certificateCorrelationService.relinkDevicesForSource(
                source, completedAt, correlationId, staleDevicesRetired);
        state.setSyncStatus(partial ? SyncStatus.PARTIAL : SyncStatus.OK);
        state.setCompletedAt(completedAt);
        state.setUpdatedAt(completedAt);
        if (!partial) {
            state.setLastError(null);
        }
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_COMPLETED, state.getSyncStatus().name(),
                Map.of("syncXref", state.getSyncXref(),
                        "processedDeviceCount", state.getProcessedDeviceCount(),
                        "failedDeviceCount", state.getFailedDeviceCount(),
                        "processedBatchCount", state.getProcessedBatchCount()),
                completedAt, correlationId, state.getSyncXref() + ":completed");
        log.info("Device sync finalized: source={} sync={} status={} devices={} failed={} "
                        + "batches={} correlation={}",
                source.getSourceXref(), state.getSyncXref(), state.getSyncStatus(),
                state.getProcessedDeviceCount(), state.getFailedDeviceCount(),
                state.getProcessedBatchCount(), correlationId);
    }

    private void failChecksumConflict(IotDeviceSource source,
                                      IotDeviceSourceSyncState state,
                                      int batchIndex) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setSyncStatus(SyncStatus.FAILED);
        state.setCompletedAt(now);
        state.setLastError("Batch " + batchIndex + " was redelivered with a different checksum");
        state.setUpdatedAt(now);
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_FAILED, SyncStatus.FAILED.name(),
                Map.of("syncXref", state.getSyncXref(), "batchIndex", batchIndex,
                        "reason", "CHECKSUM_CONFLICT"),
                now, null, state.getSyncXref() + ":checksum-conflict:" + batchIndex);
    }

    private void failCountMismatch(IotDeviceSource source,
                                   IotDeviceSourceSyncState state,
                                   String correlationId,
                                   int accountedDevices) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setSyncStatus(SyncStatus.FAILED);
        state.setCompletedAt(now);
        state.setLastError("Sync completion counts are lower than the accepted response data");
        state.setUpdatedAt(now);
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_FAILED, SyncStatus.FAILED.name(),
                Map.of("syncXref", state.getSyncXref(),
                        "expectedDeviceCount", state.getExpectedDeviceCount(),
                        "accountedDeviceCount", accountedDevices,
                        "expectedBatchCount", state.getExpectedBatchCount(),
                        "processedBatchCount", state.getProcessedBatchCount(),
                        "reason", "COUNT_MISMATCH"),
                now, correlationId, state.getSyncXref() + ":count-mismatch");
    }

    /**
     * Ends the sync as FAILED when its response could not be processed, in its own transaction because
     * the failed one rolled back; otherwise the sync stays RUNNING until the running-sync timeout.
     */
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void markProcessingFailed(String organizationId, String sourceXref, String syncXref,
                                     String correlationId, Throwable cause) {
        IotDeviceSource source = findSource(parseOrgId(organizationId), sourceXref);
        if (source == null || syncXref == null) {
            return;
        }
        IotDeviceSourceSyncState state = syncStateRepository.lockBySourceId(source.getId()).orElse(null);
        if (!ownsCurrentSync(state, syncXref)) {
            return;
        }
        String detail = cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
        failInvalidPayload(source, state, correlationId, "PROCESSING_FAILED",
                "The sync response could not be saved: " + (detail.length() > 500 ? detail.substring(0, 500) : detail));
    }

    private void failInvalidPayload(IotDeviceSource source,
                                    IotDeviceSourceSyncState state,
                                    String correlationId,
                                    String reason,
                                    String message) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setSyncStatus(SyncStatus.FAILED);
        state.setCompletedAt(now);
        state.setLastError(message);
        state.setUpdatedAt(now);
        syncStateRepository.save(state);
        eventService.record(source, DeviceSourceEventType.SYNC_FAILED, SyncStatus.FAILED.name(),
                Map.of("syncXref", state.getSyncXref(), "reason", reason),
                now, correlationId, state.getSyncXref() + ":" + reason.toLowerCase());
    }

    private static boolean completionCountsMatch(IotDeviceSourceSyncState state,
                                                 DeviceIdentitySyncResponseComplete complete) {
        return Integer.valueOf(complete.getTotalDevices()).equals(state.getExpectedDeviceCount())
                && Integer.valueOf(complete.getTotalBatches()).equals(state.getExpectedBatchCount());
    }

    private static boolean hasExactBatchRange(Map<String, String> batches, int expectedCount) {
        if (batches.size() != expectedCount) {
            return false;
        }
        for (int index = 0; index < expectedCount; index++) {
            if (!batches.containsKey(String.valueOf(index))) {
                return false;
            }
        }
        return true;
    }

    private String checksum(List<DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto> devices) {
        try {
            byte[] payload = objectMapper.writeValueAsBytes(devices);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Could not verify a device sync batch checksum", exception);
        }
    }

    private IotDeviceSource findSource(Long organizationId, String sourceXref) {
        if (organizationId == null || sourceXref == null || sourceXref.isBlank()) {
            return null;
        }
        return sourceRepository.findBySourceXrefAndOrganizationId(sourceXref, organizationId).orElse(null);
    }

    private static boolean ownsCurrentSync(IotDeviceSourceSyncState state, String syncXref) {
        return state != null && syncXref.equals(state.getSyncXref())
                && state.getCompletedAt() == null;
    }

    private void ensureStarted(IotDeviceSource source,
                               IotDeviceSourceSyncState state,
                               String correlationId) {
        boolean transitioned = state.getSyncStatus() == SyncStatus.PENDING;
        if (state.getStartedAt() == null) {
            state.setStartedAt(state.getRequestedAt());
        }
        if (transitioned) {
            state.setSyncStatus(SyncStatus.RUNNING);
            OffsetDateTime now = OffsetDateTime.now(clock);
            eventService.record(source, DeviceSourceEventType.SYNC_STARTED, SyncStatus.RUNNING.name(),
                    Map.of("syncXref", state.getSyncXref(), "confirmedBy", "FIRST_RESPONSE"),
                    now, correlationId, state.getSyncXref() + ":started");
        }
    }

    private Map<String, String> readBatches(String json) {
        if (json == null || json.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, String>>() {});
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored sync batch state is invalid JSON", exception);
        }
    }

    private String writeBatches(Map<String, String> batches) {
        try {
            return objectMapper.writeValueAsString(batches);
        } catch (JacksonException exception) {
            throw new IllegalStateException("Could not serialize sync batch state", exception);
        }
    }

    private static List<DeviceIdentityPayload> toPayloads(
            List<DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto> entries) {
        if (entries == null || entries.isEmpty()) {
            return List.of();
        }
        List<DeviceIdentityPayload> devices = new ArrayList<>(entries.size());
        entries.forEach(entry -> devices.add(toPayload(entry)));
        return devices;
    }

    private static DeviceIdentityPayload toPayload(DeviceIdentitySyncResponsePart.DeviceIdentityEntryDto entry) {
        return new DeviceIdentityPayload(
                entry.getExternalId(), entry.getEntraObjectId(), entry.getEntraDeviceId(),
                entry.getSerialNumber(), entry.getDeviceName(), entry.getManagedDeviceName(),
                entry.getOperatingSystem(), entry.getOsVersion(), entry.getManufacturer(), entry.getModel(),
                entry.getDeviceCategory(), entry.getEnrollmentProfileName(), entry.getImei(), entry.getMeid(),
                entry.getWifiMac(), entry.getOwnerType(), entry.getComplianceState(),
                entry.getRegistrationState(), entry.getManagementAgent(), entry.getManagementType(),
                entry.getDeviceOwnership(), entry.getEnrollmentType(), entry.getIsEncrypted(),
                entry.getIsSupervised(), entry.getJailbrokenState(),
                parseTimestamp(entry.getMdmEnrolledAt()), parseTimestamp(entry.getMdmLastSyncAt()),
                null, entry.getProviderAttributes());
    }

    private static OffsetDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private static Long parseOrgId(String value) {
        try {
            long parsed = Long.parseLong(value);
            return parsed > 0 ? parsed : null;
        } catch (RuntimeException exception) {
            return null;
        }
    }
}
