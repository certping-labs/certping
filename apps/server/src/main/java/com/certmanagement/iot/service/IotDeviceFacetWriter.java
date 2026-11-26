// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.dto.request.ConnectedThingAttributes;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceConnectedThing;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.enums.DeviceFacet;
import com.certmanagement.iot.enums.ThingFormFactor;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import tools.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Writes the optional one-to-one detail rows declared by a device-source adapter.
 *
 * <p>A new facet row is persisted rather than saved. Both rows key on {@code device_id}, so their
 * identifier is assigned rather than generated and {@code JpaRepository.save} would take them
 * through {@code merge} — one SELECT per device before the INSERT. The caller has already proven
 * the row is absent by preloading the page, so the extra read is a pure N+1 on first sync.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class IotDeviceFacetWriter {
    private final EntityManager entityManager;
    private final DeviceFieldNormalizer normalizer;
    private final ObjectMapper objectMapper;

    void write(IotDevice device,
               PlatformAdapter adapter,
               DeviceIdentityPayload payload,
               IotDeviceEndpointPosture existingPosture,
               IotDeviceConnectedThing existingConnectedThing) {
        Set<DeviceFacet> facets = adapter.facets();
        if (facets.contains(DeviceFacet.ENDPOINT_POSTURE)) {
            writePosture(device, adapter, payload, existingPosture);
        }
        if (facets.contains(DeviceFacet.CONNECTED_THING)) {
            writeConnectedThing(device, payload, existingConnectedThing);
        }
    }

    private void writeConnectedThing(IotDevice device,
                                     DeviceIdentityPayload payload,
                                     IotDeviceConnectedThing existingConnectedThing) {
        ConnectedThingAttributes source = payload.connectedThing();
        if (source == null) {
            return;
        }
        boolean isNew = existingConnectedThing == null;
        IotDeviceConnectedThing thing = isNew
                ? IotDeviceConnectedThing.builder().deviceId(device.getId()).build()
                : existingConnectedThing;
        setIfPresent(normalizer.text(source.attestationType()), thing::setAttestationType);
        setIfPresent(normalizer.text(source.hubOrAccountRef()), thing::setHubOrAccountRef);
        setIfPresent(normalizer.text(source.thingType()), thing::setThingType);
        setIfPresent(parseFormFactor(source.formFactor()), thing::setFormFactor);
        setIfPresent(normalizer.timestamp(source.lastConnectedAt()), thing::setLastConnectedAt);
        setIfPresent(serialize(source.customAttributes()), thing::setCustomAttributes);
        thing.setConnectivityState(normalizer.text(source.connectivityState()));
        if (isNew) {
            entityManager.persist(thing);
        }
    }

    private void writePosture(
            IotDevice device,
            PlatformAdapter adapter,
            DeviceIdentityPayload payload,
            IotDeviceEndpointPosture existingPosture) {
        String complianceRaw = normalizer.text(payload.complianceState());
        boolean isNew = existingPosture == null;
        IotDeviceEndpointPosture posture = isNew
                ? IotDeviceEndpointPosture.builder().deviceId(device.getId()).build()
                : existingPosture;
        setIfPresent(normalizer.text(payload.operatingSystem()), posture::setOperatingSystem);
        setIfPresent(normalizer.textOrSentinel(payload.osVersion()), posture::setOsVersion);
        setIfPresent(normalizer.text(payload.managementAgent()), posture::setManagementAgent);
        setIfPresent(normalizer.text(payload.enrollmentType()), posture::setEnrollmentType);
        setIfPresent(normalizer.timestamp(payload.mdmEnrolledAt()), posture::setMdmEnrolledAt);
        setIfPresent(normalizer.timestamp(payload.mdmLastSyncAt()), posture::setMdmLastSyncAt);
        setIfPresent(serializeVendorAttributes(payload), posture::setVendorAttributes);
        posture.setComplianceState(adapter.mapCompliance(complianceRaw));
        posture.setComplianceStateRaw(complianceRaw);
        posture.setIsEncrypted(payload.isEncrypted());
        posture.setIsSupervised(payload.isSupervised());
        posture.setJailbrokenState(normalizer.text(payload.jailbrokenState()));
        if (isNew) {
            entityManager.persist(posture);
        }
    }

    private ThingFormFactor parseFormFactor(String raw) {
        String normalized = normalizer.text(raw);
        if (normalized == null) {
            return null;
        }
        try {
            return ThingFormFactor.valueOf(normalized.toUpperCase());
        } catch (IllegalArgumentException exception) {
            log.debug("Unrecognised thing form factor '{}', leaving unset", normalized);
            return null;
        }
    }

    private String serializeVendorAttributes(DeviceIdentityPayload payload) {
        Map<String, Object> vendor = new LinkedHashMap<>();
        putIfPresent(vendor, "managedDeviceName", normalizer.text(payload.managedDeviceName()));
        putIfPresent(vendor, "deviceCategory", normalizer.textOrSentinel(payload.deviceCategory()));
        putIfPresent(vendor, "enrollmentProfileName", normalizer.text(payload.enrollmentProfileName()));
        putIfPresent(vendor, "registrationState", normalizer.text(payload.registrationState()));
        putIfPresent(vendor, "managementType", normalizer.text(payload.managementType()));
        putIfPresent(vendor, "deviceOwnership", normalizer.text(payload.deviceOwnership()));
        putIfPresent(vendor, "imei", normalizer.text(payload.imei()));
        putIfPresent(vendor, "meid", normalizer.text(payload.meid()));
        putIfPresent(vendor, "wifiMac", normalizer.text(payload.wifiMac()));
        return serialize(vendor);
    }

    private String serialize(Map<String, ?> value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JacksonException exception) {
            log.warn("Could not serialize device facet attributes: {}", exception.getMessage());
            return null;
        }
    }

    private static <T> void setIfPresent(T value, Consumer<T> setter) {
        if (value != null) {
            setter.accept(value);
        }
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
