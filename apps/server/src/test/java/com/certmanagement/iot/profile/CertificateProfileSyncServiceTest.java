// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceEvent;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.repository.IotDeviceSourceEventRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateProfileSyncServiceTest {
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceEventRepository eventRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private FeatureFlagService featureFlagService;
    @Mock private CertificateProfileMessageDispatcher dispatcher;

    private CertificateProfileSyncService service;
    private IotDeviceProperties properties;

    @BeforeEach
    void setUp() {
        properties = new IotDeviceProperties();
        properties.setProfileResponseTimeout(Duration.ofHours(2));
        service = new CertificateProfileSyncService(
                sourceRepository, eventRepository, eventService, featureFlagService,
                dispatcher, new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build()),
                properties,
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void manualRequestReturnsRunningRequestWithoutPublishingADuplicate() {
        IotDeviceSource source = source(DeviceSourceProvider.INTUNE);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(featureFlagService.isEnabled(
                FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, 42L)).thenReturn(true);
        when(eventRepository.findLatestOpenProfileSync(10L)).thenReturn(Optional.of(
                IotDeviceSourceEvent.builder()
                        .detailJson("{\"requestXref\":\"profile_sync_existing\"}")
                        .build()));
        when(eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "profile_sync_existing", DeviceSourceEventType.PROFILE_SYNC_STARTED))
                .thenReturn(true);

        String requestXref = service.request(42L, "source-1", 7L);

        assertThat(requestXref).isEqualTo("profile_sync_existing");
        verify(dispatcher, never()).publishDiscovery(10L, "profile_sync_existing");
        verify(eventService, never()).record(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void initialRequestIgnoresUnsupportedProviderWithoutThrowing() {
        when(sourceRepository.findById(10L))
                .thenReturn(Optional.of(source(DeviceSourceProvider.AWS_IOT)));

        service.requestInitialIfNeeded(10L, 7L);

        verify(eventService, never()).record(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
        verify(dispatcher, never()).publishDiscovery(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void staleStartedRequestIsFailedBeforeAFreshRequestIsPrepared() {
        IotDeviceSource source = source(DeviceSourceProvider.INTUNE);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(featureFlagService.isEnabled(
                FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, 42L)).thenReturn(true);
        when(eventRepository.findLatestOpenProfileSync(10L)).thenReturn(Optional.of(
                IotDeviceSourceEvent.builder()
                        .occurredAt(OffsetDateTime.parse("2026-08-24T21:00:00Z"))
                        .detailJson("{\"requestXref\":\"profile_sync_stale\"}")
                        .build()));

        String requestXref = service.request(42L, "source-1", 7L);

        assertThat(requestXref).startsWith("profile_sync_")
                .isNotEqualTo("profile_sync_stale");
        verify(eventService).record(
                org.mockito.ArgumentMatchers.eq(source),
                org.mockito.ArgumentMatchers.eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                org.mockito.ArgumentMatchers.eq("FAILED"),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq("profile_sync_stale"),
                org.mockito.ArgumentMatchers.eq("profile_sync_stale:failed"));
    }

    private static IotDeviceSource source(DeviceSourceProvider provider) {
        return IotDeviceSource.builder()
                .id(10L)
                .sourceXref("source-1")
                .organizationId(42L)
                .provider(provider)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("primary")
                .displayName("Primary")
                .status(DeviceSourceStatus.ACTIVE)
                .build();
    }
}
