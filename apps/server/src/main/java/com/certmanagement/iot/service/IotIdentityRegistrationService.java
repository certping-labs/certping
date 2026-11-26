// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.adapter.PlatformAdapterFactory;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.dto.request.IdentityRegistrationRequest;
import com.certmanagement.iot.dto.response.DeviceUpsertResult;
import com.certmanagement.iot.dto.response.IdentityRegistrationResult;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceConnectedThing;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceConnectedThingRepository;
import com.certmanagement.iot.repository.IotDeviceEndpointPostureRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import com.certmanagement.iot.validation.DeviceIdentityPayloadValidator;
import jakarta.persistence.EntityManager;
import org.hibernate.Session;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Entry point for a page of device identities from the agent.
 *
 * <p>Resolves the platform, preloads the page's stored state, and applies each payload through
 * {@link IotDeviceUpsertService} in one bounded transaction. Platform-specific mapping stays in
 * the adapter.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotIdentityRegistrationService {
    static final int MAX_BATCH_SIZE = 1_000;
    /** Rows per JDBC round trip while applying a page. Only ever set on this path's session. */
    private static final int SYNC_JDBC_BATCH_SIZE = 50;

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceEndpointPostureRepository postureRepository;
    private final IotDeviceConnectedThingRepository connectedThingRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceUpsertService upsertService;
    private final IotOrphanBatchService orphanBatchService;
    private final PlatformAdapterFactory adapterFactory;
    private final DeviceFieldNormalizer normalizer;
    private final DeviceIdentityPayloadValidator payloadValidator;
    private final Clock clock;
    private final EntityManager entityManager;

    // ═══════════════════════════════════════════════════════════════════════
    //  Batch ingest
    // ═══════════════════════════════════════════════════════════════════════

    /** Preloads one bounded page and applies it without per-device repository reads. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public IdentityRegistrationResult upsertBatch(Long organizationId,
                                                  IdentityRegistrationRequest request,
                                                  ActorSource actorSource,
                                                  String correlationId) {
        if (request.devices() == null || request.devices().isEmpty()
                || request.devices().size() > MAX_BATCH_SIZE) {
            throw new IllegalArgumentException(
                    "devices must contain between 1 and " + MAX_BATCH_SIZE + " entries");
        }

        IotDeviceSource source = sourceRepository
                .findBySourceXrefAndOrganizationId(request.sourceXref(), organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Unknown device source: " + request.sourceXref()));

        // Scoped to this transaction rather than configured globally. Every sync re-stamps a whole
        // page across iot_device and its posture rows, and each of those updates is otherwise its
        // own round trip: batching turns 2000 statements into 2. It is set on the session because
        // the reason for it is local to this path, and the rest of the application should not have
        // its write behaviour — or its constraint-violation reporting — changed as a side effect.
        entityManager.unwrap(Session.class).setJdbcBatchSize(SYNC_JDBC_BATCH_SIZE);

        PlatformAdapter adapter = adapterFactory.getAdapter(source.getProvider());
        BatchState batchState = loadBatchState(source.getId(), request.devices());

        OffsetDateTime seenAt = OffsetDateTime.now(clock);
        List<DeviceUpsertResult> results = new ArrayList<>(request.devices().size());
        Set<String> processedSourceDeviceIds = new HashSet<>();
        int created = 0, updated = 0, unchanged = 0, failed = 0;

        for (DeviceIdentityPayload payload : request.devices()) {
            String validationError = payloadValidator.validate(payload);
            if (validationError != null) {
                results.add(DeviceUpsertResult.failed(
                        payload == null ? null : payload.externalId(), validationError));
                failed++;
                continue;
            }
            String sourceDeviceId = normalizer.text(payload.externalId());
            if (sourceDeviceId != null && !processedSourceDeviceIds.add(sourceDeviceId)) {
                results.add(DeviceUpsertResult.failed(
                        payload.externalId(), "externalId is duplicated in this batch"));
                failed++;
                continue;
            }
            DeviceUpsertResult result = upsertService.upsertOne(
                    organizationId, source, adapter, payload,
                    batchState.devicesBySourceId().get(sourceDeviceId),
                    batchState.posturesByDeviceId(), batchState.connectedThingsByDeviceId(),
                    seenAt, actorSource, correlationId);
            results.add(result);
            switch (result.outcome()) {
                case CREATED   -> created++;
                case UPDATED   -> updated++;
                case UNCHANGED -> unchanged++;
                case FAILED    -> failed++;
            }
        }

        return new IdentityRegistrationResult(
                request.syncXref(), created, updated, unchanged, failed, results);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Orphan detection
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Marks devices a completed <b>full</b> sync did not return.
     *
     * <p>Only ever runs after a FULL sweep. A partial result set would make every device that
     * simply was not returned look like it had vanished.
     *
     * <p>ORPHANED is not deletion. A device can disappear from its platform while still holding
     * a live certificate, so the row is kept and becomes a revocation candidate.
     */
    public int markOrphans(IotDeviceSource source, OffsetDateTime syncStartedAt, String correlationId) {
        int orphaned = 0;
        int batchCount;
        do {
            batchCount = orphanBatchService.markNextBatch(
                    source.getId(), syncStartedAt, OffsetDateTime.now(clock), correlationId);
            orphaned += batchCount;
        } while (batchCount == IotOrphanBatchService.BATCH_SIZE);

        log.info("IoT orphan detection: source={} orphaned={}",
                source.getSourceXref(), orphaned);
        return orphaned;
    }

    private BatchState loadBatchState(Long sourceId, List<DeviceIdentityPayload> payloads) {
        List<String> sourceDeviceIds = payloads.stream()
                .filter(Objects::nonNull)
                .filter(payload -> payloadValidator.validate(payload) == null)
                .map(DeviceIdentityPayload::externalId)
                .map(normalizer::text)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        // Archived rows included: uk_iot_device_source_id still reserves their source device id,
        // so a device the source reports again has to update that row rather than insert a second
        // one. IotDeviceUpsertService un-archives it.
        Map<String, IotDevice> devicesBySourceId = sourceDeviceIds.isEmpty()
                ? Map.of()
                : deviceRepository
                        .findBySourceDeviceIdsIncludingArchived(sourceId, sourceDeviceIds)
                        .stream().collect(Collectors.toMap(
                                IotDevice::getSourceDeviceId, Function.identity()));
        List<Long> deviceIds = devicesBySourceId.values().stream().map(IotDevice::getId).toList();
        Map<Long, IotDeviceEndpointPosture> posturesByDeviceId = deviceIds.isEmpty()
                ? Map.of()
                : postureRepository.findByDeviceIdIn(deviceIds).stream().collect(Collectors.toMap(
                        IotDeviceEndpointPosture::getDeviceId, Function.identity()));
        Map<Long, IotDeviceConnectedThing> connectedThingsByDeviceId = deviceIds.isEmpty()
                ? Map.of()
                : connectedThingRepository.findByDeviceIdIn(deviceIds).stream().collect(
                        Collectors.toMap(IotDeviceConnectedThing::getDeviceId, Function.identity()));
        return new BatchState(devicesBySourceId, posturesByDeviceId, connectedThingsByDeviceId);
    }

    private record BatchState(
            Map<String, IotDevice> devicesBySourceId,
            Map<Long, IotDeviceEndpointPosture> posturesByDeviceId,
            Map<Long, IotDeviceConnectedThing> connectedThingsByDeviceId) {
    }
}
