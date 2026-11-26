// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.dto.response.DeviceDetail;
import com.certmanagement.iot.dto.response.DeviceListItem;
import com.certmanagement.iot.dto.response.IotSummary;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceConnectedThing;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.entity.IotDeviceOwner;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceHealthStatus;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceConnectedThingRepository;
import com.certmanagement.iot.repository.IotDeviceEndpointPostureRepository;
import com.certmanagement.iot.repository.IotDeviceOwnerRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceSyncStateRepository;
import com.certmanagement.service.audit.IotAuditRecorder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Read side of the registry: inventory, detail and dashboard tiles. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceQueryService {

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceSyncStateRepository syncStateRepository;
    private final IotDeviceOwnerRepository ownerRepository;
    private final IotDeviceEndpointPostureRepository postureRepository;
    private final IotDeviceConnectedThingRepository connectedThingRepository;
    private final IotDeviceSourceHealthStatusRepository healthRepository;
    private final IotDeviceEventService eventService;
    private final IotDeviceProperties properties;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    @Transactional(readOnly = true)
    public Page<DeviceListItem> list(Long organizationId,
                                     String sourceXref,
                                     DeviceStatus status,
                                     ComplianceState complianceState,
                                     String operatingSystem,
                                     String search,
                                     Pageable pageable) {

        Long sourceId = sourceXref == null ? null
                : sourceRepository
                    .findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                    .map(IotDeviceSource::getId)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Device source not found"));

        Map<Long, String> sourceNames = sourceRepository
                .findAllByOrganizationIdOrderByCreatedAtDesc(organizationId)
                .stream()
                .collect(HashMap::new,
                        (map, source) -> map.put(source.getId(), source.getDisplayName()),
                        HashMap::putAll);

        Page<IotDevice> page = deviceRepository.search(
                organizationId, sourceId, status, complianceState, operatingSystem, search, pageable);

        List<Long> deviceIds = page.getContent().stream().map(IotDevice::getId).toList();
        Map<Long, IotDeviceEndpointPosture> postures = postureRepository.findAllById(deviceIds).stream()
                .collect(Collectors.toMap(IotDeviceEndpointPosture::getDeviceId, Function.identity()));
        // Not findAllById: that ignores is_deleted and would render an owner whose personal
        // data has been erased.
        Map<Long, IotDeviceOwner> owners = ownerRepository.findByDeviceIdInAndIsDeletedFalse(deviceIds).stream()
                .collect(Collectors.toMap(IotDeviceOwner::getDeviceId, Function.identity()));
        return page.map(device -> toListItem(
                device,
                postures.get(device.getId()),
                owners.get(device.getId()),
                sourceNames.get(device.getDeviceSourceId())));
    }

    @Transactional(readOnly = true)
    public DeviceDetail detail(Long organizationId, String deviceXref) {
        return toDetail(requireByXref(organizationId, deviceXref));
    }

    /** Builds the complete non-history API view without exposing internal database identifiers. */
    private DeviceDetail toDetail(IotDevice device) {
        IotDeviceSource source = sourceRepository.findById(device.getDeviceSourceId())
                .orElseThrow(() -> new IllegalStateException("Device source is missing"));
        IotDeviceEndpointPosture posture = postureRepository.findByDeviceId(device.getId()).orElse(null);
        IotDeviceConnectedThing connectedThing = connectedThingRepository
                .findByDeviceId(device.getId()).orElse(null);
        IotDeviceOwner owner = ownerRepository
                .findByDeviceIdAndIsDeletedFalse(device.getId()).orElse(null);
        return new DeviceDetail(
                device.getDeviceXref(),
                toSource(source),
                device.getSourceDeviceId(),
                parseJson(device.getSourceIdentifiersJson()),
                device.getDeviceClass() == null ? null : device.getDeviceClass().name(),
                device.getSerialNumber(),
                device.getDeviceName(),
                device.getManufacturer(),
                device.getModel(),
                device.getOwnership() == null ? null : device.getOwnership().name(),
                device.getStatus() == null ? null : device.getStatus().name(),
                Boolean.TRUE.equals(device.getIsDeleted()),
                device.getRegisteredAt(),
                device.getLastSeenInSourceAt(),
                device.getDecommissionedAt(),
                toPosture(posture),
                toConnectedThing(connectedThing),
                toOwner(owner),
                new DeviceDetail.ProviderData(
                        device.getProviderAttributesSchemaVersion(),
                        device.getProviderAttributesUpdatedAt(),
                        parseJson(device.getProviderAttributesJson())),
                device.getCreatedAt(),
                device.getUpdatedAt());
    }

    /**
     * Resolves a device for the detail and activity views, archived rows included.
     *
     * <p>An archived device is hidden from the inventory, not from someone holding its link: a
     * certificate still points at it, and an archive an operator cannot open is an archive they
     * cannot undo.
     */
    @Transactional(readOnly = true)
    public IotDevice requireByXref(Long organizationId, String deviceXref) {
        return deviceRepository
                .findByDeviceXrefIncludingArchived(deviceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));
    }

    @Transactional(readOnly = true)
    public IotSummary summary(Long organizationId) {
        Map<String, Long> byStatus = enumCounts(DeviceStatus.values(),
                deviceRepository.countByStatus(organizationId));
        Map<String, Long> byProvider = rowsToMap(deviceRepository.countByProvider(organizationId));
        Map<String, Long> byDeviceClass = rowsToMap(deviceRepository.countByDeviceClass(organizationId));
        Map<String, Long> byOwnership = rowsToMap(deviceRepository.countByOwnership(organizationId));
        Map<String, Long> byOperatingSystem = rowsToMap(
                postureRepository.countByOperatingSystem(organizationId));
        Map<String, Long> byCompliance = rowsToMap(
                postureRepository.countByComplianceState(organizationId));

        long total = byStatus.values().stream().mapToLong(Long::longValue).sum();

        List<IotDeviceSource> sources = sourceRepository
                .findAllByOrganizationIdOrderByCreatedAtDesc(organizationId);
        List<Long> sourceIds = sources.stream().map(IotDeviceSource::getId).toList();
        Map<Long, Long> sourceCounts = sourceIds.isEmpty() ? Map.of()
                : deviceRepository.countByDeviceSourceIds(sourceIds).stream()
                        .collect(Collectors.toMap(row -> (Long) row[0], row -> (Long) row[1]));
        List<IotSummary.SourceDeviceCount> bySource = sources.stream()
                .map(source -> new IotSummary.SourceDeviceCount(
                        source.getSourceXref(), source.getDisplayName(), source.getProvider().name(),
                        sourceCounts.getOrDefault(source.getId(), 0L)))
                .toList();
        OffsetDateTime lastSync = syncStateRepository.findAllById(sourceIds).stream()
                .map(com.certmanagement.iot.entity.IotDeviceSourceSyncState::getCompletedAt)
                .filter(Objects::nonNull)
                .max(OffsetDateTime::compareTo)
                .orElse(null);

        return new IotSummary(
                total,
                byStatus.getOrDefault(DeviceStatus.REGISTERED.name(), 0L),
                byStatus,
                byProvider,
                bySource,
                byDeviceClass,
                byOwnership,
                byOperatingSystem,
                byCompliance,
                booleanBreakdown(postureRepository.countByEncryption(organizationId)),
                booleanBreakdown(postureRepository.countBySupervision(organizationId)),
                sourceOverview(sources),
                lastSync);
    }

    /**
     * Retires a device. Distinct from deletion: the history and any certificate record
     * are kept for the compliance window.
     */
    @Transactional
    public DeviceDetail decommission(Long organizationId, String deviceXref, Long actorUserId) {
        IotDevice device = deviceRepository.lockByDeviceXrefAndOrganizationId(deviceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));
        if (device.getStatus() == DeviceStatus.DECOMMISSIONED) {
            return toDetail(device);
        }
        DeviceStatus previousStatus = device.getStatus();
        device.setStatus(DeviceStatus.DECOMMISSIONED);
        device.setDecommissionedAt(OffsetDateTime.now(clock));
        deviceRepository.save(device);
        iotAudit.deviceDecommissioned(device, previousStatus);

        eventService.record(device, DeviceEventType.DECOMMISSIONED, ActorSource.UI, actorUserId,
                Map.of(
                        "previousStatus", previousStatus.name(),
                        "newStatus", DeviceStatus.DECOMMISSIONED.name()),
                null);
        return toDetail(device);
    }

    private DeviceDetail.Source toSource(IotDeviceSource source) {
        return new DeviceDetail.Source(
                source.getSourceXref(), source.getProvider().name(), source.getSourceCategory().name(),
                source.getConnectionProfileRef(), source.getDisplayName(), source.getDescription(),
                parseJson(source.getConfigurationMetadataJson()), Boolean.TRUE.equals(source.getSyncEnabled()),
                source.getStatus().name());
    }

    private DeviceDetail.EndpointPosture toPosture(IotDeviceEndpointPosture posture) {
        if (posture == null) {
            return null;
        }
        return new DeviceDetail.EndpointPosture(
                posture.getOperatingSystem(), posture.getOsVersion(),
                posture.getComplianceState() == null ? null : posture.getComplianceState().name(),
                posture.getComplianceStateRaw(), posture.getIsEncrypted(), posture.getIsSupervised(),
                posture.getJailbrokenState(), posture.getManagementAgent(), posture.getEnrollmentType(),
                posture.getMdmEnrolledAt(), posture.getMdmLastSyncAt(),
                parseJson(posture.getVendorAttributes()));
    }

    private DeviceDetail.ConnectedThing toConnectedThing(IotDeviceConnectedThing thing) {
        if (thing == null) {
            return null;
        }
        return new DeviceDetail.ConnectedThing(
                thing.getAttestationType(), thing.getHubOrAccountRef(), thing.getThingType(),
                thing.getFormFactor() == null ? null : thing.getFormFactor().name(),
                thing.getConnectivityState(), thing.getLastConnectedAt(),
                parseJson(thing.getCustomAttributes()));
    }

    private static DeviceDetail.Owner toOwner(IotDeviceOwner owner) {
        return owner == null ? null : new DeviceDetail.Owner(
                owner.getOwnerUpn(), owner.getOwnerEmail(), owner.getOwnerDisplayName(), owner.getUpdatedAt());
    }

    private IotSummary.SourceOverview sourceOverview(List<IotDeviceSource> sources) {
        Map<Long, IotDeviceSourceHealthStatus> healthBySource = healthRepository
                .findAllById(sources.stream().map(IotDeviceSource::getId).toList())
                .stream().collect(Collectors.toMap(
                        IotDeviceSourceHealthStatus::getDeviceSourceId, Function.identity()));
        OffsetDateTime staleBefore = OffsetDateTime.now(clock).minus(properties.getHealthStaleAfter());
        long syncEnabled = sources.stream().filter(source -> Boolean.TRUE.equals(source.getSyncEnabled())).count();
        long healthy = 0;
        long degraded = 0;
        long unhealthy = 0;
        long stale = 0;
        long unknown = 0;
        for (IotDeviceSource source : sources) {
            IotDeviceSourceHealthStatus health = healthBySource.get(source.getId());
            if (health == null || health.getHealthStatus() == null) {
                unknown++;
            } else if (health.getReceivedAt() == null || health.getReceivedAt().isBefore(staleBefore)) {
                stale++;
            } else {
                switch (health.getHealthStatus()) {
                    case HEALTHY -> healthy++;
                    case DEGRADED -> degraded++;
                    case UNHEALTHY -> unhealthy++;
                    case UNKNOWN -> unknown++;
                }
            }
        }
        return new IotSummary.SourceOverview(
                sources.size(), syncEnabled, healthy, degraded, unhealthy, stale, unknown);
    }

    private static IotSummary.BooleanBreakdown booleanBreakdown(List<Object[]> rows) {
        long yes = 0;
        long no = 0;
        long unknown = 0;
        for (Object[] row : rows) {
            if (Boolean.TRUE.equals(row[0])) {
                yes = (Long) row[1];
            } else if (Boolean.FALSE.equals(row[0])) {
                no = (Long) row[1];
            } else {
                unknown = (Long) row[1];
            }
        }
        return new IotSummary.BooleanBreakdown(yes, no, unknown);
    }

    private static Map<String, Long> rowsToMap(List<Object[]> rows) {
        Map<String, Long> counts = new LinkedHashMap<>();
        rows.forEach(row -> counts.put(row[0] == null ? "UNKNOWN" : row[0].toString(), (Long) row[1]));
        return counts;
    }

    private static <E extends Enum<E>> Map<String, Long> enumCounts(E[] values, List<Object[]> rows) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (E value : values) {
            counts.put(value.name(), 0L);
        }
        counts.putAll(rowsToMap(rows));
        return counts;
    }

    private Map<String, Object> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception exception) {
            log.warn("Could not deserialize stored IoT metadata: {}", exception.getMessage());
            return Map.of();
        }
    }

    private DeviceListItem toListItem(IotDevice device,
                                      IotDeviceEndpointPosture posture,
                                      IotDeviceOwner owner,
                                      String platformDisplayName) {
        return new DeviceListItem(
                device.getDeviceXref(),
                device.getDeviceName(),
                device.getSerialNumber(),
                device.getDeviceClass() == null ? null : device.getDeviceClass().name(),
                posture == null ? null : posture.getOperatingSystem(),
                posture == null ? null : posture.getOsVersion(),
                device.getModel(),
                owner == null ? null : owner.getOwnerUpn(),
                owner == null ? null : owner.getOwnerDisplayName(),
                posture == null || posture.getComplianceState() == null
                        ? null : posture.getComplianceState().name(),
                device.getStatus() == null ? null : device.getStatus().name(),
                platformDisplayName,
                device.getLastSeenInSourceAt());
    }
}
