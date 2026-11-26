// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.messaging.DeviceSourceHealthMessage;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceSourceHealthServiceTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC);

    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceHealthStatusRepository healthRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private FeatureFlagService featureFlagService;
    @Mock private com.certmanagement.iot.revocation.IotIntunePollStateService intunePollStateService;

    @BeforeEach
    void enableIotFeatureFlags() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null))
                .thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L))
                .thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_PROVIDER_INTUNE, 42L))
                .thenReturn(true);
    }

    @Test
    void storesOnlyAllowlistedNonSecretMetadata() {
        DeviceSourceHealthMessage message = validMessage();
        message.setConfigurationMetadata(Map.of(
                "apiHost", "graph.microsoft.com",
                "tenantId", "tenant-secret-id",
                "clientSecret", "never-store"));
        message.setHealthMetadata(Map.of(
                "managedDevicesReadValidated", true,
                "entraDevicesReadValidated", true,
                "graphApiVersion", "v1.0",
                "certificateProfileGraphApiVersion", "beta",
                "certificateProfilesReadValidated", false,
                "certificateProfilesReadErrorCode", "INTUNE_CONFIGURATION_PERMISSION_DENIED",
                "permissions", List.of(
                        Map.of("name", "DeviceManagementManagedDevices.Read.All", "granted", true),
                        Map.of("name", "DeviceManagementManagedDevices.PrivilegedOperations.All",
                                "granted", false)),
                "userEmail", "person@example.com"));
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary").displayName("Primary").build();
        when(organizationRepository.existsById(42L)).thenReturn(true);
        when(sourceRepository.findByOrganizationIdAndConnectionProfileRef(42L, "intune-primary"))
                .thenReturn(Optional.empty(), Optional.of(source));
        when(sourceRepository.upsertAdvertisement(anyString(), eq(42L), eq("INTUNE"),
                eq("ENDPOINT_MANAGEMENT"), eq("intune-primary"), eq("Primary"),
                any(), anyString(), any(), any(), any())).thenReturn(1);
        when(healthRepository.upsertIfNewer(any(), anyString(), anyString(), any(), any(),
                anyString(), anyString(), anyLong(), any(), any(), any(), any(), any()))
                .thenReturn(1);
        IotDeviceSourceHealthService service = service();

        service.handle(message, 7L);

        ArgumentCaptor<String> configuration = ArgumentCaptor.forClass(String.class);
        verify(sourceRepository).upsertAdvertisement(anyString(), eq(42L), eq("INTUNE"),
                eq("ENDPOINT_MANAGEMENT"), eq("intune-primary"), eq("Primary"),
                any(), configuration.capture(), any(), any(), eq(7L));
        ArgumentCaptor<String> health = ArgumentCaptor.forClass(String.class);
        verify(healthRepository).upsertIfNewer(eq(10L), eq("health-1"), eq("HEALTHY"),
                any(), any(), health.capture(), eq("agent-1"), eq(1L), any(), any(), any(), any(), any());
        assertThat(configuration.getValue()).contains("graph.microsoft.com")
                .doesNotContain("tenant-secret-id", "never-store");
        assertThat(health.getValue()).contains(
                        "managedDevicesReadValidated", "entraDevicesReadValidated",
                        "graphApiVersion", "certificateProfileGraphApiVersion", "beta",
                        "certificateProfilesReadValidated",
                        "INTUNE_CONFIGURATION_PERMISSION_DENIED",
                        "DeviceManagementManagedDevices.PrivilegedOperations.All")
                .doesNotContain("person@example.com");
    }

    @Test
    void rejectsAHealthClockFarInTheFutureBeforeWritingAnything() {
        DeviceSourceHealthMessage message = validMessage();
        message.setCheckStartedAt("2099-01-01T00:00:00Z");
        message.setObservedAt("2099-01-01T00:00:01Z");
        message.setPublishedAt("2099-01-01T00:00:02Z");
        when(organizationRepository.existsById(42L)).thenReturn(true);

        service().handle(message);

        verify(sourceRepository, never()).upsertAdvertisement(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
        verify(healthRepository, never()).upsertIfNewer(
                any(), any(), any(), any(), any(), any(), any(), anyLong(),
                any(), any(), any(), any(), any());
    }

    @Test
    void dropsHealthBeforeParsingWhenDeploymentDisablesIot() {
        DeviceSourceHealthMessage message = validMessage();
        message.setOrganizationId("org-a");
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null))
                .thenReturn(false);

        service().handle(message);

        verify(organizationRepository, never()).existsById(anyLong());
        verify(sourceRepository, never()).upsertAdvertisement(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void dropsHealthWhenOrganizationDisablesIot() {
        when(organizationRepository.existsById(42L)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L))
                .thenReturn(false);

        service().handle(validMessage());

        verify(sourceRepository, never()).upsertAdvertisement(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void dropsIntuneHealthWhenProviderFlagIsDisabled() {
        when(organizationRepository.existsById(42L)).thenReturn(true);
        when(featureFlagService.isEnabled(FeatureFlags.IOT_PROVIDER_INTUNE, 42L))
                .thenReturn(false);

        service().handle(validMessage());

        verify(sourceRepository, never()).upsertAdvertisement(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    private IotDeviceSourceHealthService service() {
        return new IotDeviceSourceHealthService(
                sourceRepository, healthRepository, eventService, organizationRepository,
                featureFlagService, new DeviceSourceMetadataSanitizer(), JsonMapper.builderWithJackson2Defaults().build(),
                new IotDeviceProperties(), intunePollStateService, CLOCK);
    }

    private static DeviceSourceHealthMessage validMessage() {
        DeviceSourceHealthMessage message = new DeviceSourceHealthMessage();
        message.setHealthXref("health-1");
        message.setOrganizationId("42");
        message.setConnectionProfileRef("intune-primary");
        message.setProvider("INTUNE");
        message.setSourceCategory("ENDPOINT_MANAGEMENT");
        message.setDisplayName("Primary");
        message.setHealthStatus("HEALTHY");
        message.setProviderStatus("CONNECTED");
        message.setAgentInstanceXref("agent-1");
        message.setAgentSequence(1L);
        message.setCheckStartedAt("2026-08-24T09:59:58Z");
        message.setObservedAt("2026-08-24T09:59:59Z");
        message.setPublishedAt("2026-08-24T10:00:00Z");
        message.setResponseTimeMs(1L);
        return message;
    }
}
