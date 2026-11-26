// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.DeviceIdentityEntry;
import com.certping.agent.platform.DeviceIdentityConnector;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.platform.DeviceSourceProfile;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IntuneDeviceIdentityConnectorTest {
    private static final DeviceSourceProfile PROFILE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary", null, Map.of());

    @Test
    void healthVerifiesBothGraphPermissionsAndReturnsSafeEvidence() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        String token = token(IntuneDeviceIdentityConnector.MANAGED_DEVICES_READ,
                IntuneDeviceIdentityConnector.ENTRA_DEVICES_READ,
                IntuneDeviceIdentityConnector.CONFIGURATION_READ_WRITE,
                IntuneDeviceIdentityConnector.PRIVILEGED_OPERATIONS);
        when(graph.acquireToken("tenant", "client", "secret")).thenReturn(token);
        when(graph.probeManagedDevices(token)).thenReturn(1);
        IntuneCertificateProfileClient profileClient = mock(IntuneCertificateProfileClient.class);
        when(profileClient.probeReadPermission(token)).thenReturn(1);
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, profileClient, mock(ManagedDeviceMapper.class),
                sessionProvider(graph, credentials()));

        DeviceIdentityConnector.ConnectionTestResult result = connector.testConnectionDetails(PROFILE);

        assertThat(result.visibleDeviceSample()).isEqualTo(1);
        assertThat(result.healthStatus()).isEqualTo("HEALTHY");
        assertThat(result.metadata()).containsEntry("permissionsValidated", true)
                .containsEntry("graphApiVersion", "v1.0")
                .containsEntry("certificateProfileGraphApiVersion", "beta")
                .containsEntry("certificateProfilesVisibleSample", 1);
        assertThat((List<?>) result.metadata().get("permissions")).hasSize(4);
        verify(graph).probeManagedDevices(token);
        verify(graph).probeEntraDevices(token);
    }

    @Test
    void missingEnvironmentCredentialsAreReportedAsConfigurationFailure() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        DeviceSourceCredentialRegistry registry = mock(DeviceSourceCredentialRegistry.class);
        when(registry.requireCredentialsJson("intune-primary", DevicePlatformType.INTUNE))
                .thenThrow(new PermanentAgentException(
                        "PLATFORM_NOT_CONFIGURED", "No local credentials are configured"));
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, mock(IntuneCertificateProfileClient.class), mock(ManagedDeviceMapper.class),
                new IntuneSessionProvider(graph, registry, JsonMapper.builderWithJackson2Defaults().build()));

        assertThatThrownBy(() -> connector.testConnection(PROFILE))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        exception -> assertThat(exception.getErrorCode())
                                .isEqualTo("PLATFORM_NOT_CONFIGURED"));
        verify(graph, never()).acquireToken("tenant", "client", "secret");
    }

    @Test
    void healthIdentifiesTheMissingEntraReadPermission() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        String token = token(IntuneDeviceIdentityConnector.MANAGED_DEVICES_READ,
                IntuneDeviceIdentityConnector.CONFIGURATION_READ_WRITE,
                IntuneDeviceIdentityConnector.PRIVILEGED_OPERATIONS);
        when(graph.acquireToken("tenant", "client", "secret")).thenReturn(token);
        when(graph.probeManagedDevices(token)).thenReturn(1);
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, mock(IntuneCertificateProfileClient.class), mock(ManagedDeviceMapper.class),
                sessionProvider(graph, credentials()));

        DeviceIdentityConnector.ConnectionTestResult result = connector.testConnectionDetails(PROFILE);

        assertThat(result.healthStatus()).isEqualTo("UNHEALTHY");
        assertThat(result.providerStatus()).isEqualTo("REQUIRED_PERMISSION_MISSING");
        assertThat(result.metadata()).containsEntry("permissionsValidated", false);
        verify(graph, never()).probeEntraDevices(token);
    }

    @Test
    void missingProfilePermissionIsReportedWithoutHidingHealthyDeviceDiscovery() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        IntuneCertificateProfileClient profileClient = mock(IntuneCertificateProfileClient.class);
        String token = token(IntuneDeviceIdentityConnector.MANAGED_DEVICES_READ,
                IntuneDeviceIdentityConnector.ENTRA_DEVICES_READ,
                IntuneDeviceIdentityConnector.PRIVILEGED_OPERATIONS);
        when(graph.acquireToken("tenant", "client", "secret")).thenReturn(token);
        when(graph.probeManagedDevices(token)).thenReturn(2);
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, profileClient, mock(ManagedDeviceMapper.class),
                sessionProvider(graph, credentials()));

        DeviceIdentityConnector.ConnectionTestResult result =
                connector.testConnectionDetails(PROFILE);

        assertThat(result.visibleDeviceSample()).isEqualTo(2);
        assertThat(result.healthStatus()).isEqualTo("DEGRADED");
        assertThat(result.metadata()).containsEntry("permissionsValidated", false);
        verify(profileClient, never()).probeReadPermission(token);
    }

    @Test
    void nonPermissionProbeFailureIsNotMisreportedAsMissingConsent() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        String token = token(IntuneDeviceIdentityConnector.MANAGED_DEVICES_READ,
                IntuneDeviceIdentityConnector.ENTRA_DEVICES_READ);
        when(graph.acquireToken("tenant", "client", "secret")).thenReturn(token);
        when(graph.probeManagedDevices(token)).thenThrow(
                new PermanentAgentException("PLATFORM_RESPONSE_INVALID", "Malformed Graph response"));
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, mock(IntuneCertificateProfileClient.class), mock(ManagedDeviceMapper.class),
                sessionProvider(graph, credentials()));

        assertThatThrownBy(() -> connector.testConnectionDetails(PROFILE))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        exception -> assertThat(exception.getErrorCode())
                                .isEqualTo("PLATFORM_RESPONSE_INVALID"));
    }

    @Test
    void malformedCredentialJsonIsPermanentWithoutEchoingTheSecret() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, mock(IntuneCertificateProfileClient.class),
                mock(ManagedDeviceMapper.class),
                sessionProvider(graph, "not-json-super-secret"));

        assertThatThrownBy(() -> connector.testConnection(PROFILE))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageNotContaining("not-json-super-secret")
                .hasNoCause();
    }

    @Test
    void deviceSyncOmitsRetirePendingRowsFromTheCurrentInventory() {
        IntuneGraphClient graph = mock(IntuneGraphClient.class);
        ManagedDeviceMapper mapper = mock(ManagedDeviceMapper.class);
        String token = token(IntuneDeviceIdentityConnector.MANAGED_DEVICES_READ);
        when(graph.acquireToken("tenant", "client", "secret")).thenReturn(token);
        Map<String, Object> current = Map.of(
                "id", "managed-device-1", "managementState", "managed");
        Map<String, Object> retiring = Map.of(
                "id", "retiring-device-1", "managementState", "retirePending");
        doAnswer(invocation -> {
            Consumer<List<Map<String, Object>>> consumer = invocation.getArgument(1);
            consumer.accept(List.of(current, retiring));
            return null;
        }).when(graph).streamManagedDevices(
                org.mockito.ArgumentMatchers.eq(token), org.mockito.ArgumentMatchers.any());
        when(graph.fetchEntraDevicesForManagedPage(token, List.of(current)))
                .thenReturn(Map.of());
        DeviceIdentityEntry entry = DeviceIdentityEntry.builder()
                .externalId("managed-device-1")
                .build();
        when(mapper.toEntry(current, Map.of())).thenReturn(entry);
        IntuneDeviceIdentityConnector connector = new IntuneDeviceIdentityConnector(
                graph, mock(IntuneCertificateProfileClient.class), mapper,
                sessionProvider(graph, credentials()));
        List<DeviceIdentityEntry> received = new ArrayList<>();

        connector.streamDevices(PROFILE, received::addAll);

        assertThat(received).containsExactly(entry);
        verify(graph).fetchEntraDevicesForManagedPage(token, List.of(current));
        verify(mapper, never()).toEntry(
                org.mockito.ArgumentMatchers.eq(retiring), org.mockito.ArgumentMatchers.any());
    }

    private static IntuneSessionProvider sessionProvider(
            IntuneGraphClient graph, String credentialsJson) {
        DeviceSourceCredentialRegistry registry = mock(DeviceSourceCredentialRegistry.class);
        when(registry.requireCredentialsJson("intune-primary", DevicePlatformType.INTUNE))
                .thenReturn(credentialsJson);
        return new IntuneSessionProvider(graph, registry, JsonMapper.builderWithJackson2Defaults().build());
    }

    private static String credentials() {
        return "{\"tenantId\":\"tenant\",\"clientId\":\"client\","
                + "\"clientSecret\":\"secret\"}";
    }

    private static String token(String... roles) {
        String roleJson = java.util.Arrays.stream(roles)
                .map(role -> "\"" + role + "\"")
                .collect(java.util.stream.Collectors.joining(","));
        String payload = "{\"roles\":[" + roleJson + "]}";
        return "e30." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".signature";
    }
}
