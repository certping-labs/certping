// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.dto.response.DeviceUpsertResult;
import com.certmanagement.iot.dto.response.UpsertOutcome;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.entity.IotDeviceConnectedThing;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceOwnership;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Applies one validated device payload inside the caller's bounded batch transaction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceUpsertService {

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceEventService eventService;
    private final IotDeviceFacetWriter facetWriter;
    private final DeviceFieldNormalizer normalizer;
    private final ObjectMapper objectMapper;

    private static final int MAX_PROVIDER_ATTRIBUTE_LENGTH = 2_000;


    DeviceUpsertResult upsertOne(Long organizationId,
                                         IotDeviceSource source,
                                         PlatformAdapter adapter,
                                         DeviceIdentityPayload payload,
                                         IotDevice existingDevice,
                                         Map<Long, IotDeviceEndpointPosture> posturesByDeviceId,
                                         Map<Long, IotDeviceConnectedThing> connectedThingsByDeviceId,
                                         OffsetDateTime seenAt,
                                         ActorSource actorSource,
                                         String correlationId) {

        String externalId = normalizer.text(payload.externalId());
        if (externalId == null) {
            return DeviceUpsertResult.failed(payload.externalId(), "externalId is required");
        }

        if (existingDevice != null) {
            return applyUpdate(existingDevice,
                    posturesByDeviceId.get(existingDevice.getId()),
                    connectedThingsByDeviceId.get(existingDevice.getId()),
                    adapter, payload, seenAt, actorSource, correlationId, externalId);
        }

        // A device the source has never reported.
        IotDevice device = IotDevice.builder()
                .deviceXref(newXref())
                .organizationId(organizationId)
                .deviceSourceId(source.getId())
                .sourceDeviceId(externalId)
                .sourceIdentifiersJson(serializeJson(adapter.sourceIdentifiers(payload)))
                .deviceClass(adapter.deviceClass())
                .status(DeviceStatus.REGISTERED)
                .registeredAt(seenAt)
                .lastSeenInSourceAt(seenAt)
                .build();
        applyPayload(device, adapter, payload, seenAt);
        deviceRepository.save(device);
        facetWriter.write(device, adapter, payload, null, null);

        eventService.record(device, DeviceEventType.DEVICE_DISCOVERED, actorSource,
                null, Map.of(
                        "sourceXref", source.getSourceXref(),
                        "provider", source.getProvider().name(),
                        "initialStatus", DeviceStatus.REGISTERED.name()),
                correlationId);
        return DeviceUpsertResult.ok(externalId, device.getDeviceXref(), UpsertOutcome.CREATED);
    }

    /** Diffs the device, and writes an event only if something meaningful moved. */
    private DeviceUpsertResult applyUpdate(IotDevice device,
                                           IotDeviceEndpointPosture posture,
                                           IotDeviceConnectedThing connectedThing,
                                           PlatformAdapter adapter,
                                           DeviceIdentityPayload payload,
                                           OffsetDateTime seenAt,
                                           ActorSource actorSource,
                                           String correlationId,
                                           String externalId) {

        ComplianceState previousCompliance = posture == null ? null : posture.getComplianceState();
        boolean wasOrphaned = device.getStatus() == DeviceStatus.ORPHANED;
        // An operator archived this row out of the inventory while its source had stopped
        // reporting it. The source is reporting it again, so the reason to hide it is gone.
        boolean wasArchived = Boolean.TRUE.equals(device.getIsDeleted());

        ComplianceState nextCompliance = adapter.mapCompliance(payload.complianceState());
        DeviceOwnership nextOwnership = parseOwnership(payload.ownerType(), payload.deviceOwnership());

        String previousOs        = posture == null ? null : posture.getOperatingSystem();
        String previousOsVersion = posture == null ? null : posture.getOsVersion();
        String previousAgent     = posture == null ? null : posture.getManagementAgent();
        String previousEnrolType = posture == null ? null : posture.getEnrollmentType();

        Map<String, Map<String, Object>> diff = new LinkedHashMap<>();
        record Field(String name, Object before, Object after) {}

        // The `after` for a preserved field is what the write will actually store, not what the
        // source sent. A stale enrollment reports "" for these; applyPayload keeps the last known
        // value, so reporting a change to null here would log a change that never happened and
        // mark the device UPDATED on every sync forever.
        List<Field> tracked = List.of(
                new Field("deviceName",        device.getDeviceName(),
                        keep(device.getDeviceName(), normalizer.text(payload.deviceName()))),
                new Field("serialNumber",      device.getSerialNumber(),
                        keep(device.getSerialNumber(), normalizer.text(payload.serialNumber()))),
                new Field("manufacturer",      device.getManufacturer(),
                        keep(device.getManufacturer(), normalizer.text(payload.manufacturer()))),
                new Field("model",             device.getModel(),
                        keep(device.getModel(), normalizer.text(payload.model()))),
                new Field("ownership",         device.getOwnership(),
                        keep(device.getOwnership(), nextOwnership)),
                new Field("operatingSystem",   previousOs,
                        keep(previousOs, normalizer.text(payload.operatingSystem()))),
                new Field("osVersion",         previousOsVersion,
                        keep(previousOsVersion, normalizer.textOrSentinel(payload.osVersion()))),
                new Field("managementAgent",   previousAgent,
                        keep(previousAgent, normalizer.text(payload.managementAgent()))),
                new Field("enrollmentType",    previousEnrolType,
                        keep(previousEnrolType, normalizer.text(payload.enrollmentType()))),

                // Live security state: written unconditionally, so a disappearance is a real
                // change and must be recorded as one.
                new Field("complianceState",   previousCompliance, nextCompliance),
                new Field("isEncrypted",       posture == null ? null : posture.getIsEncrypted(),
                        payload.isEncrypted()),
                new Field("isSupervised",      posture == null ? null : posture.getIsSupervised(),
                        payload.isSupervised()));

        for (Field field : tracked) {
            if (normalizer.changed(field.before(), field.after())) {
                Map<String, Object> change = new LinkedHashMap<>();
                change.put("from", field.before());
                change.put("to", field.after());
                diff.put(field.name(), change);
            }
        }

        // Always stamp, even when nothing else moved, so a device that is
        // present but unchanged is not orphaned by the next full sync.
        device.setLastSeenInSourceAt(seenAt);
        device.setSourceIdentifiersJson(mergeSourceIdentifiers(
                device.getSourceIdentifiersJson(), adapter.sourceIdentifiers(payload)));

        if (diff.isEmpty() && !wasOrphaned && !wasArchived) {
            // Nothing in the diff: refresh provider metadata and facets, but write no event. Operational
            // fields such as MDM check-in time, threat state, certificate expiry and device
            // identifiers can change without any normalized field in the event diff moving.
            // Skipping applyPayload/facetWriter here left those snapshots permanently stale.
            applyPayload(device, adapter, payload, seenAt);
            facetWriter.write(device, adapter, payload, posture, connectedThing);
            return DeviceUpsertResult.ok(externalId, device.getDeviceXref(), UpsertOutcome.UNCHANGED);
        }

        applyPayload(device, adapter, payload, seenAt);
        if (wasOrphaned) {
            device.setStatus(DeviceStatus.REGISTERED);
        }
        if (wasArchived) {
            device.setIsDeleted(false);
        }
        facetWriter.write(device, adapter, payload, posture, connectedThing);

        if (wasOrphaned || wasArchived) {
            Map<String, Object> restored = new LinkedHashMap<>();
            restored.put("previousStatus",
                    wasOrphaned ? DeviceStatus.ORPHANED.name() : device.getStatus().name());
            restored.put("wasArchived", wasArchived);
            eventService.record(device, DeviceEventType.DEVICE_RESTORED, actorSource,
                    null, Map.copyOf(restored), correlationId);
        }
        if (diff.containsKey("complianceState")) {
            eventService.record(device, DeviceEventType.COMPLIANCE_CHANGED, actorSource, null,
                    Map.of("from", String.valueOf(previousCompliance),
                           "to", String.valueOf(nextCompliance)),
                    correlationId);
        }
        Map<String, Map<String, Object>> residual = new LinkedHashMap<>(diff);
        residual.remove("complianceState");
        if (!residual.isEmpty()) {
            eventService.record(device, DeviceEventType.DEVICE_UPDATED, actorSource,
                    null, residual, correlationId);
        }

        return DeviceUpsertResult.ok(externalId, device.getDeviceXref(), UpsertOutcome.UPDATED);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Copies the payload onto the device, keeping the last known value where the source
     * reported nothing.
     *
     * <p>A stale enrollment returns {@code serialNumber: ""}, {@code operatingSystem: ""} and
     * so on, which normalises to null. Assigning that blindly erased the serial — the device's
     * match key — along with its manufacturer and model, which is precisely the record needed
     * to work out why the device went stale. A source going quiet is not the same as a device
     * losing its identity, so absent values are ignored rather than written.
     */
    private void applyPayload(IotDevice device, PlatformAdapter adapter,
                              DeviceIdentityPayload payload, OffsetDateTime seenAt) {
        if (device.getDeviceClass() == null) {
            device.setDeviceClass(adapter.deviceClass());
        }
        setIfPresent(normalizer.text(payload.serialNumber()), device::setSerialNumber);
        setIfPresent(normalizer.text(payload.deviceName()), device::setDeviceName);
        setIfPresent(normalizer.text(payload.manufacturer()), device::setManufacturer);
        setIfPresent(normalizer.text(payload.model()), device::setModel);
        setIfPresent(parseOwnership(payload.ownerType(), payload.deviceOwnership()), device::setOwnership);
        device.setLastSeenInSourceAt(seenAt);
        String providerAttributes = serializeProviderAttributes(adapter, payload.providerAttributes());
        if (providerAttributes != null) {
            device.setProviderAttributesJson(providerAttributes);
            device.setProviderAttributesSchemaVersion(1);
            device.setProviderAttributesUpdatedAt(seenAt);
        }
    }

    /** Assigns only when the source actually reported a value. */
    private static <T> void setIfPresent(T value, java.util.function.Consumer<T> setter) {
        if (value != null) {
            setter.accept(value);
        }
    }

    /** What a preserved field will hold after the write: the new value, or the old one if absent. */
    private static <T> T keep(T current, T incoming) {
        return incoming != null ? incoming : current;
    }

    /**
     * Merges the identifiers this payload carried over the ones already stored, per key.
     *
     * <p>Replacing the whole document would mean one incomplete Graph response destroys an
     * identifier it simply did not mention. That matters more here than for the other preserved
     * fields: the Entra device id is what identifies this row's replacement if the device is ever
     * removed and enrolled again, and it is the only identifier that survives that event, so
     * losing it makes the device permanently unrepairable. An Entra device id names one Entra
     * device object, so keeping a value the source stopped reporting can only ever match the same
     * physical device.
     */
    private String mergeSourceIdentifiers(String storedJson, Map<String, ?> reported) {
        if (reported == null || reported.isEmpty()) {
            return storedJson;
        }
        Map<String, Object> merged = new LinkedHashMap<>();
        if (storedJson != null && !storedJson.isBlank()) {
            try {
                merged.putAll(objectMapper.readValue(storedJson, new TypeReference<>() {}));
            } catch (JacksonException ex) {
                log.warn("Replacing unreadable stored device identifiers: {}", ex.getMessage());
            }
        }
        merged.putAll(reported);
        return serializeJson(merged);
    }

    private String serializeJson(Map<String, ?> value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JacksonException ex) {
            log.warn("Could not serialize device attributes: {}", ex.getMessage());
            return null;
        }
    }

    private DeviceOwnership parseOwnership(String ownerType, String deviceOwnership) {
        String raw = normalizer.ownerType(ownerType);
        if (raw == null) {
            raw = normalizer.ownerType(deviceOwnership);
        }
        if (raw == null) {
            return null;
        }
        try {
            return DeviceOwnership.valueOf(raw);
        } catch (IllegalArgumentException ex) {
            log.debug("Unrecognised ownership '{}', storing UNKNOWN", raw);
            return DeviceOwnership.UNKNOWN;
        }
    }

    /** Server-side allowlist. The agent's filtering is useful, but the queue remains untrusted input. */
    private String serializeProviderAttributes(PlatformAdapter adapter, Map<String, Object> raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        Map<String, Object> safe = new LinkedHashMap<>();
        for (String key : adapter.providerAttributeKeys()) {
            Object value = raw.get(key);
            if (value instanceof String text) {
                safe.put(key, text.length() <= MAX_PROVIDER_ATTRIBUTE_LENGTH
                        ? text : text.substring(0, MAX_PROVIDER_ATTRIBUTE_LENGTH));
            } else if (value instanceof Number || value instanceof Boolean) {
                safe.put(key, value);
            }
        }
        if (safe.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(safe);
        } catch (JacksonException ex) {
            log.warn("Could not serialise provider device attributes: {}", ex.getMessage());
            return null;
        }
    }

    private String newXref() {
        return "dev_" + UUID.randomUUID().toString().replace("-", "");
    }
}
