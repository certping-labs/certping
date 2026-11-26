// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.dto.response.UpsertOutcome;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceClass;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceUpsertServiceTest {
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private IotDeviceFacetWriter facetWriter;
    @Mock private PlatformAdapter adapter;

    /**
     * The Entra device id is the only identifier that survives a re-enrollment, so it is the key
     * the certificate repair matches a replacement on. A Graph response that reports some other
     * identifier without it must not take that key away — losing it makes the device permanently
     * unrepairable.
     */
    @Test
    void aNewDeviceHasNoVersionSoSaveInsertsItInsteadOfMerging() {
        assertThat(IotDevice.builder().build().getRowVersion()).isNull();
    }

    @Test
    void anIdentifierTheSourceDidNotReportThisTimeIsKept() {
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").provider(DeviceSourceProvider.INTUNE).build();
        IotDevice existing = IotDevice.builder()
                .id(100L).deviceXref("dev_1").organizationId(42L).deviceSourceId(10L)
                .sourceDeviceId("device-1").status(DeviceStatus.REGISTERED)
                .deviceClass(DeviceClass.MANAGED_ENDPOINT)
                .sourceIdentifiersJson(
                        "{\"entraDeviceId\":\"entra-device-1\",\"entraObjectId\":\"object-old\"}")
                .build();
        // This sync reports only the object id.
        when(adapter.sourceIdentifiers(org.mockito.ArgumentMatchers.any()))
                .thenReturn(Map.of("entraObjectId", "object-new"));
        IotDeviceUpsertService service = new IotDeviceUpsertService(
                deviceRepository, eventService, facetWriter,
                new DeviceFieldNormalizer(), JsonMapper.builderWithJackson2Defaults().build());

        service.upsertOne(42L, source, adapter, payload(), existing, Map.of(), Map.of(),
                OffsetDateTime.parse("2026-08-24T10:00:00Z"), ActorSource.AGENT, "correlation-1");

        assertThat(existing.getSourceIdentifiersJson())
                .contains("\"entraDeviceId\":\"entra-device-1\"")
                .contains("\"entraObjectId\":\"object-new\"");
    }

    @Test
    void createsOneDeviceScopedToTheSourceAndSanitizesProviderAttributes() {
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L)
                .sourceXref("source-1")
                .provider(DeviceSourceProvider.INTUNE)
                .build();
        when(adapter.sourceIdentifiers(org.mockito.ArgumentMatchers.any()))
                .thenReturn(Map.of("entraDeviceId", "entra-device-1"));
        when(adapter.deviceClass()).thenReturn(DeviceClass.MANAGED_ENDPOINT);
        when(adapter.providerAttributeKeys()).thenReturn(Set.of("customProviderField"));
        IotDeviceUpsertService service = new IotDeviceUpsertService(
                deviceRepository, eventService, facetWriter,
                new DeviceFieldNormalizer(), JsonMapper.builderWithJackson2Defaults().build());
        OffsetDateTime seenAt = OffsetDateTime.parse("2026-08-24T10:00:00Z");

        var result = service.upsertOne(
                42L, source, adapter, payload(), null, Map.of(), Map.of(),
                seenAt, ActorSource.AGENT, "correlation-1");

        ArgumentCaptor<IotDevice> saved = ArgumentCaptor.forClass(IotDevice.class);
        verify(deviceRepository).save(saved.capture());
        assertThat(result.outcome()).isEqualTo(UpsertOutcome.CREATED);
        assertThat(saved.getValue().getDeviceSourceId()).isEqualTo(10L);
        assertThat(saved.getValue().getSourceDeviceId()).isEqualTo("intune-device-1");
        assertThat(saved.getValue().getSerialNumber()).isEqualTo("SERIAL-1");
        assertThat(saved.getValue().getSourceIdentifiersJson()).contains("entraDeviceId");
        assertThat(saved.getValue().getProviderAttributesJson())
                .contains("customProviderField")
                .doesNotContain("userPrincipalName", "activationLockBypassCode", "lastSyncDateTime");
        verify(facetWriter).write(saved.getValue(), adapter, payload(), null, null);
        verify(eventService).record(
                saved.getValue(), DeviceEventType.DEVICE_DISCOVERED,
                ActorSource.AGENT, null,
                Map.of(
                        "sourceXref", "source-1",
                        "provider", "INTUNE",
                        "initialStatus", "REGISTERED"),
                "correlation-1");
    }

    @Test
    void unchangedDeviceStillRefreshesProviderMetadataAndFacetsWithoutAnEvent() {
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L)
                .sourceXref("source-1")
                .provider(DeviceSourceProvider.INTUNE)
                .build();
        IotDevice existing = IotDevice.builder()
                .id(7L)
                .deviceXref("device-1")
                .organizationId(42L)
                .deviceSourceId(10L)
                .sourceDeviceId("intune-device-1")
                .serialNumber("SERIAL-1")
                .deviceName("Finance MacBook")
                .manufacturer("Apple")
                .model("MacBook Air")
                .status(DeviceStatus.REGISTERED)
                .providerAttributesJson("{\"managementState\":\"old\"}")
                .build();
        when(adapter.sourceIdentifiers(org.mockito.ArgumentMatchers.any()))
                .thenReturn(Map.of("entraDeviceId", "entra-device-1"));
        when(adapter.providerAttributeKeys()).thenReturn(Set.of("customProviderField"));
        IotDeviceUpsertService service = new IotDeviceUpsertService(
                deviceRepository, eventService, facetWriter,
                new DeviceFieldNormalizer(), JsonMapper.builderWithJackson2Defaults().build());
        OffsetDateTime seenAt = OffsetDateTime.parse("2026-08-24T11:00:00Z");

        var result = service.upsertOne(
                42L, source, adapter, payloadWithoutPostureDiff(), existing, Map.of(), Map.of(), seenAt,
                ActorSource.AGENT, "correlation-2");

        assertThat(result.outcome()).isEqualTo(UpsertOutcome.UNCHANGED);
        assertThat(existing.getProviderAttributesJson()).contains("customProviderField");
        assertThat(existing.getProviderAttributesUpdatedAt()).isEqualTo(seenAt);
        assertThat(existing.getLastSeenInSourceAt()).isEqualTo(seenAt);
        verify(deviceRepository, never()).save(existing);
        verify(facetWriter).write(existing, adapter, payloadWithoutPostureDiff(), null, null);
        verifyNoInteractions(eventService);
    }

    private static DeviceIdentityPayload payload() {
        return new DeviceIdentityPayload(
                "intune-device-1", "entra-object-1", "entra-device-1", "SERIAL-1",
                "Finance MacBook", null, "macOS", "15.6.1", "Apple", "MacBook Air",
                null, null, null, null, null, "COMPANY", "compliant", null,
                "mdm", "MDM", "Company", null, true, false, "Unknown",
                null, null, null,
                Map.of(
                        "customProviderField", "kept",
                        "userPrincipalName", "owner@example.invalid",
                        "activationLockBypassCode", "secret",
                        "lastSyncDateTime", "2026-08-24T10:00:00Z"));
    }

    private static DeviceIdentityPayload payloadWithoutPostureDiff() {
        return new DeviceIdentityPayload(
                "intune-device-1", "entra-object-1", "entra-device-1", "SERIAL-1",
                "Finance MacBook", null, null, null, "Apple", "MacBook Air",
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                null, null, null,
                Map.of("customProviderField", "refreshed"));
    }
}
