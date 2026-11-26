// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Keeps source and health metadata useful while excluding credentials and arbitrary payloads. */
@Component
class DeviceSourceMetadataSanitizer {
    private static final int MAX_VALUE_LENGTH = 500;
    private static final Set<String> CONFIGURATION_KEYS = Set.of(
            "apiHost", "cloud", "environment", "organizationLabel", "region",
            "tenantLabel", "workspaceLabel");
    private static final Set<String> HEALTH_KEYS = Set.of(
            "apiVersion", "graphApiVersion", "certificateProfileGraphApiVersion",
            "cloud", "permissionsValidated",
            "managedDevicesReadValidated", "entraDevicesReadValidated", "visibleDeviceSample",
            "certificateProfilesReadValidated", "certificateProfilesVisibleSample",
            "certificateProfilesReadErrorCode");
    private static final Set<String> INTUNE_PERMISSIONS = Set.of(
            "DeviceManagementManagedDevices.Read.All",
            "Device.Read.All",
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementManagedDevices.PrivilegedOperations.All");

    Map<String, Object> configuration(Map<String, Object> metadata) {
        return allow(metadata, CONFIGURATION_KEYS);
    }

    Map<String, Object> health(Map<String, Object> metadata) {
        Map<String, Object> safe = new LinkedHashMap<>(allow(metadata, HEALTH_KEYS));
        List<Map<String, Object>> permissions = permissions(metadata == null
                ? null : metadata.get("permissions"));
        if (!permissions.isEmpty()) {
            safe.put("permissions", permissions);
        }
        return Map.copyOf(safe);
    }

    private Map<String, Object> allow(Map<String, Object> metadata, Set<String> allowedKeys) {
        if (metadata == null || metadata.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> safe = new LinkedHashMap<>();
        metadata.forEach((key, value) -> {
            if (allowedKeys.contains(key) && isScalar(value)) {
                safe.put(key, truncate(value));
            }
        });
        return safe;
    }

    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    private static Object truncate(Object value) {
        if (!(value instanceof String text) || text.length() <= MAX_VALUE_LENGTH) {
            return value;
        }
        return text.substring(0, MAX_VALUE_LENGTH);
    }

    private static List<Map<String, Object>> permissions(Object value) {
        if (!(value instanceof List<?> values) || values.size() > INTUNE_PERMISSIONS.size()) {
            return List.of();
        }
        LinkedHashMap<String, Boolean> grantedByName = new LinkedHashMap<>();
        for (Object item : values) {
            if (!(item instanceof Map<?, ?> permission)) {
                return List.of();
            }
            Object name = permission.get("name");
            Object granted = permission.get("granted");
            if (!(name instanceof String permissionName)
                    || !INTUNE_PERMISSIONS.contains(permissionName)
                    || !(granted instanceof Boolean isGranted)) {
                return List.of();
            }
            grantedByName.put(permissionName, isGranted);
        }
        return grantedByName.entrySet().stream()
                .map(entry -> Map.<String, Object>of(
                        "name", entry.getKey(), "granted", entry.getValue()))
                .toList();
    }
}
