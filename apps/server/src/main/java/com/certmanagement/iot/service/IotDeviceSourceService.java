// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.dto.response.DeviceSourceDto;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceHealthStatus;
import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.service.audit.IotAuditRecorder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class IotDeviceSourceService {
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceHealthStatusRepository healthRepository;
    private final IotDeviceSourceSyncStateRepository syncRepository;
    private final IotDeviceRepository deviceRepository;
    private final IotDeviceSourceEventService eventService;
    private final IotDeviceProperties properties;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    @Transactional(readOnly = true)
    public List<DeviceSourceDto> list(Long organizationId) {
        List<IotDeviceSource> sources = sourceRepository
                .findAllByOrganizationIdOrderByCreatedAtDesc(organizationId);
        if (sources.isEmpty()) {
            return List.of();
        }
        List<Long> sourceIds = sources.stream().map(IotDeviceSource::getId).toList();
        Map<Long, IotDeviceSourceHealthStatus> healthBySource = healthRepository.findAllById(sourceIds)
                .stream().collect(Collectors.toMap(
                        IotDeviceSourceHealthStatus::getDeviceSourceId, Function.identity()));
        Map<Long, IotDeviceSourceSyncState> syncBySource = syncRepository.findAllById(sourceIds)
                .stream().collect(Collectors.toMap(
                        IotDeviceSourceSyncState::getDeviceSourceId, Function.identity()));
        Map<Long, Long> deviceCounts = deviceRepository.countByDeviceSourceIds(sourceIds).stream()
                .collect(Collectors.toMap(row -> (Long) row[0], row -> (Long) row[1]));
        return sources.stream().map(source -> toDto(
                source, healthBySource.get(source.getId()), syncBySource.get(source.getId()),
                deviceCounts.getOrDefault(source.getId(), 0L))).toList();
    }

    @Transactional(readOnly = true)
    public IotDeviceSource requireByXref(Long organizationId, String sourceXref) {
        return sourceRepository.findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device source not found"));
    }

    @Transactional(readOnly = true)
    public IotDeviceSource requireById(Long organizationId, Long sourceId) {
        return sourceRepository.findById(sourceId)
                .filter(source -> organizationId.equals(source.getOrganizationId()))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device source not found"));
    }

    @Transactional
    public DeviceSourceDto stopSync(Long organizationId, String sourceXref, Long actorUserId) {
        IotDeviceSource source = sourceRepository.lockBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device source not found"));
        if (Boolean.TRUE.equals(source.getSyncEnabled())) {
            source.setSyncEnabled(false);
            sourceRepository.save(source);
            iotAudit.syncStopped(source);
            OffsetDateTime now = OffsetDateTime.now(clock);
            eventService.record(source, DeviceSourceEventType.SYNC_DISABLED, "DISABLED",
                    Map.of("actorUserId", actorUserId), now, null,
                    "sync-disabled:" + now.toInstant());
        }
        return toDto(source, healthRepository.findById(source.getId()).orElse(null),
                syncRepository.findById(source.getId()).orElse(null),
                deviceRepository.countByDeviceSourceIdAndIsDeletedFalse(source.getId()));
    }

    private DeviceSourceDto toDto(IotDeviceSource source,
                                  IotDeviceSourceHealthStatus health,
                                  IotDeviceSourceSyncState sync,
                                  long deviceCount) {
        DeviceSourceDto.Health healthDto = health == null ? null : healthDto(health);
        DeviceSourceDto.Sync syncDto = sync == null ? null : new DeviceSourceDto.Sync(
                sync.getSyncXref(), sync.getSyncStatus().name(), sync.getRequestedAt(),
                sync.getStartedAt(), sync.getCompletedAt(), sync.getExpectedDeviceCount(),
                sync.getProcessedDeviceCount(),
                sync.getFailedDeviceCount(), sync.getProcessedBatchCount(),
                sync.getExpectedBatchCount(), Boolean.TRUE.equals(sync.getCompletionReceived()),
                sync.getLastError());
        return new DeviceSourceDto(
                source.getSourceXref(), source.getProvider().name(), source.getSourceCategory().name(),
                source.getConnectionProfileRef(), source.getDisplayName(), source.getDescription(),
                parseJson(source.getConfigurationMetadataJson()), Boolean.TRUE.equals(source.getSyncEnabled()),
                source.getStatus().name(), source.getFirstAdvertisedAt(), source.getLastAdvertisedAt(),
                healthDto, syncDto, deviceCount);
    }

    private DeviceSourceDto.Health healthDto(IotDeviceSourceHealthStatus health) {
        OffsetDateTime staleAt = health.getReceivedAt().plus(properties.getHealthStaleAfter());
        boolean stale = !OffsetDateTime.now(clock).isBefore(staleAt);
        String reported = health.getHealthStatus().name();
        Map<String, Object> metadata = new LinkedHashMap<>(parseJson(health.getHealthMetadataJson()));
        List<DeviceSourceDto.Health.Permission> permissions = permissions(metadata.remove("permissions"));
        return new DeviceSourceDto.Health(
                stale ? "STALE" : reported, reported, stale,
                health.getProviderStatus(), health.getStatusMessage(),
                permissions, Map.copyOf(metadata), health.getObservedAt(), health.getReceivedAt(),
                staleAt, health.getResponseTimeMs());
    }

    private static List<DeviceSourceDto.Health.Permission> permissions(Object value) {
        if (!(value instanceof List<?> values)) {
            return List.of();
        }
        return values.stream().filter(Map.class::isInstance).map(Map.class::cast)
                .filter(permission -> permission.get("name") instanceof String
                        && permission.get("granted") instanceof Boolean)
                .map(permission -> new DeviceSourceDto.Health.Permission(
                        (String) permission.get("name"), (Boolean) permission.get("granted")))
                .toList();
    }

    private Map<String, Object> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception exception) {
            log.warn("Could not deserialize stored source metadata: {}", exception.getMessage());
            return Map.of();
        }
    }
}
