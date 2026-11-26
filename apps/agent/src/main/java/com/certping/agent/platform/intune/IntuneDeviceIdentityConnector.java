// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.DeviceIdentityEntry;
import com.certping.agent.platform.DeviceIdentityConnector;
import com.certping.agent.platform.DeviceIdentityConnectorFor;
import com.certping.agent.platform.DeviceSourceProfile;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Microsoft Intune, via Graph.
 *
 * <p>Device inventory uses managed-device and Entra read permissions. Certificate-profile
 * management uses configuration read-write permission. Operator-requested check-in uses the
 * separately reported privileged-operations permission.
 *
 * <p>The deployment secret manager injects indexed credential JSON into this process. Neither the
 * JSON nor its fields are sent to the server.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@DeviceIdentityConnectorFor(DevicePlatformType.INTUNE)
public class IntuneDeviceIdentityConnector implements DeviceIdentityConnector {

    static final String MANAGED_DEVICES_READ = "DeviceManagementManagedDevices.Read.All";
    static final String ENTRA_DEVICES_READ = "Device.Read.All";
    static final String CONFIGURATION_READ_WRITE = "DeviceManagementConfiguration.ReadWrite.All";
    static final String PRIVILEGED_OPERATIONS =
            "DeviceManagementManagedDevices.PrivilegedOperations.All";

    private final IntuneGraphClient graphClient;
    private final IntuneCertificateProfileClient certificateProfileClient;
    private final ManagedDeviceMapper mapper;
    private final IntuneSessionProvider sessionProvider;

    /**
     * Proves the credentials work <em>and</em> that the app holds the permission the sync needs.
     *
     * <p>Probes {@code managedDevices} rather than the cheaper Entra {@code /devices}: they sit
     * behind different application permissions, and a tenant that consented to only
     * {@code Device.Read.All} would otherwise see a green connection test and then fail every
     * sync.
     */
    @Override
    public int testConnection(DeviceSourceProfile profile) {
        ConnectionTestResult result = testConnectionDetails(profile);
        if ("UNHEALTHY".equals(result.healthStatus())) {
            throw new PermanentAgentException(
                    "INTUNE_REQUIRED_PERMISSION_MISSING", result.statusMessage());
        }
        return result.visibleDeviceSample();
    }

    @Override
    public ConnectionTestResult testConnectionDetails(DeviceSourceProfile profile) {
        IntuneSession session = sessionProvider.open(profile);
        boolean managedDevicesRead = session.roles().contains(MANAGED_DEVICES_READ);
        boolean entraDevicesRead = session.roles().contains(ENTRA_DEVICES_READ);
        boolean configurationReadWrite = session.roles().contains(CONFIGURATION_READ_WRITE);
        boolean privilegedOperations = session.roles().contains(PRIVILEGED_OPERATIONS);
        int visibleDeviceSample = 0;

        if (managedDevicesRead) {
            try {
                visibleDeviceSample = graphClient.probeManagedDevices(session.token());
            } catch (PermanentAgentException exception) {
                rethrowUnlessPermissionFailure(exception, "PLATFORM_PERMISSION_DENIED");
                managedDevicesRead = false;
            }
        }
        if (entraDevicesRead) {
            try {
                graphClient.probeEntraDevices(session.token());
            } catch (PermanentAgentException exception) {
                rethrowUnlessPermissionFailure(exception, "PLATFORM_PERMISSION_DENIED");
                entraDevicesRead = false;
            }
        }
        Integer visibleProfileSample = null;
        if (configurationReadWrite) {
            try {
                visibleProfileSample = certificateProfileClient.probeReadPermission(session.token());
            } catch (PermanentAgentException exception) {
                rethrowUnlessPermissionFailure(
                        exception, "INTUNE_CONFIGURATION_PERMISSION_DENIED");
                configurationReadWrite = false;
            }
        }

        boolean inventoryReady = managedDevicesRead && entraDevicesRead;
        boolean allPermissionsReady = inventoryReady
                && configurationReadWrite && privilegedOperations;
        String healthStatus = !inventoryReady
                ? "UNHEALTHY" : allPermissionsReady ? "HEALTHY" : "DEGRADED";
        String providerStatus = !inventoryReady
                ? "REQUIRED_PERMISSION_MISSING"
                : allPermissionsReady ? "CONNECTED" : "OPTIONAL_PERMISSION_MISSING";
        String statusMessage = !inventoryReady
                ? "Required Intune inventory permissions are missing"
                : allPermissionsReady ? null
                : "Some Intune certificate-management actions are unavailable";

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("permissionsValidated", allPermissionsReady);
        metadata.put("permissions", List.of(
                permission(MANAGED_DEVICES_READ, managedDevicesRead),
                permission(ENTRA_DEVICES_READ, entraDevicesRead),
                permission(CONFIGURATION_READ_WRITE, configurationReadWrite),
                permission(PRIVILEGED_OPERATIONS, privilegedOperations)));
        metadata.put("graphApiVersion", "v1.0");
        metadata.put("certificateProfileGraphApiVersion", "beta");
        if (visibleProfileSample != null) {
            metadata.put("certificateProfilesVisibleSample", visibleProfileSample);
        }
        return new ConnectionTestResult(visibleDeviceSample, metadata,
                healthStatus, providerStatus, statusMessage);
    }

    @Override
    public void streamDevices(DeviceSourceProfile profile,
                              Consumer<List<DeviceIdentityEntry>> pageConsumer) {
        IntuneSession session = sessionProvider.open(profile);

        graphClient.streamManagedDevices(session.token(), rawPage -> {
            List<Map<String, Object>> currentDevices = rawPage.stream()
                    .filter(IntuneDeviceIdentityConnector::isCurrentDevice)
                    .toList();
            Map<String, Map<String, Object>> entraDevices =
                    graphClient.fetchEntraDevicesForManagedPage(session.token(), currentDevices);
            List<DeviceIdentityEntry> entries = new ArrayList<>(currentDevices.size());
            for (Map<String, Object> raw : currentDevices) {
                DeviceIdentityEntry entry =
                        mapper.toEntry(raw, entraDevices);
                if (entry.getExternalId() != null) {
                    entries.add(entry);
                }
            }
            pageConsumer.accept(entries);
        });
    }

    /**
     * Intune keeps a sparse managed-device row while retirement is pending. It is no longer a
     * current endpoint and a full sync must let the server mark its previous registry row orphaned.
     */
    private static boolean isCurrentDevice(Map<String, Object> managedDevice) {
        Object rawState = managedDevice.get("managementState");
        if (rawState == null) {
            return true;
        }
        return !"retirepending".equals(rawState.toString().trim().toLowerCase(Locale.ROOT));
    }

    private static Map<String, Object> permission(String name, boolean granted) {
        return Map.of("name", name, "granted", granted);
    }

    private static void rethrowUnlessPermissionFailure(
            PermanentAgentException exception, String permissionErrorCode) {
        if (!permissionErrorCode.equals(exception.getErrorCode())) {
            throw exception;
        }
    }

}
