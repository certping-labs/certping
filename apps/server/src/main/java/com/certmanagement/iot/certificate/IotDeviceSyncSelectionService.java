// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.config.IotDeviceSyncProperties;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.repository.IotDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Resolves and validates the one, many, or all device selection contract. */
@Component
@RequiredArgsConstructor
class IotDeviceSyncSelectionService {

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceSyncProperties properties;

    Selection select(Long organizationId, boolean all, DeviceSyncRequest request) {
        List<String> requested = normalized(all, request);
        List<IotDevice> devices = all
                ? allDevices(organizationId)
                : deviceRepository.findAllByOrganizationIdAndDeviceXrefInAndIsDeletedFalse(
                        organizationId, requested);
        Set<String> found = devices.stream().map(IotDevice::getDeviceXref)
                .collect(Collectors.toSet());
        List<DeviceSyncResponse.DeviceResult> missing = new ArrayList<>();
        if (!all) {
            requested.stream().filter(xref -> !found.contains(xref))
                    .map(xref -> new DeviceSyncResponse.DeviceResult(
                            xref, "SKIPPED", "DEVICE_NOT_FOUND", List.of(), null))
                    .forEach(missing::add);
        }
        return new Selection(all ? devices.size() : requested.size(), devices, missing);
    }

    private List<IotDevice> allDevices(Long organizationId) {
        int limit = properties.getMaxAllDevices();
        List<IotDevice> devices = deviceRepository
                .findAllByOrganizationIdAndIsDeletedFalseOrderById(
                        organizationId, PageRequest.of(0, limit + 1));
        if (devices.size() > limit) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "All-device sync exceeds the configured maximum of "
                            + limit);
        }
        return devices;
    }

    private List<String> normalized(boolean all, DeviceSyncRequest request) {
        List<String> requested = request == null ? List.of() : request.deviceXrefs();
        if (all && !requested.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "deviceXrefs must be empty when all=true");
        }
        if (!all && requested.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Provide at least one deviceXref or set all=true");
        }
        Set<String> normalized = requested.stream().map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (normalized.size() > properties.getMaxExplicitDevices()) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "Too many deviceXrefs; maximum is " + properties.getMaxExplicitDevices());
        }
        return List.copyOf(normalized);
    }

    record Selection(
            int selectedCount,
            List<IotDevice> devices,
            List<DeviceSyncResponse.DeviceResult> initialResults) {}
}
