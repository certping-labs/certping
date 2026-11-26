// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.adapter.PlatformAdapterFactory;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.dto.request.IdentityRegistrationRequest;
import com.certmanagement.iot.dto.response.DeviceUpsertResult;
import com.certmanagement.iot.dto.response.UpsertOutcome;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.repository.IotDeviceConnectedThingRepository;
import com.certmanagement.iot.repository.IotDeviceEndpointPostureRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import com.certmanagement.iot.validation.DeviceIdentityPayloadValidator;
import jakarta.persistence.EntityManager;
import org.hibernate.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotIdentityRegistrationServiceTest {
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceEndpointPostureRepository postureRepository;
    @Mock private IotDeviceConnectedThingRepository connectedThingRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceUpsertService upsertService;
    @Mock private IotOrphanBatchService orphanBatchService;
    @Mock private PlatformAdapterFactory adapterFactory;
    @Mock private PlatformAdapter adapter;
    @Mock private EntityManager entityManager;
    @Mock private Session session;

    private IotIdentityRegistrationService service;
    private IotDeviceSource source;

    @BeforeEach
    void setUp() {
        lenient().when(entityManager.unwrap(Session.class)).thenReturn(session);
        source = IotDeviceSource.builder().id(10L).organizationId(42L)
                .sourceXref("source-1").provider(DeviceSourceProvider.INTUNE).build();
        service = new IotIdentityRegistrationService(
                deviceRepository, postureRepository, connectedThingRepository,
                sourceRepository, upsertService, orphanBatchService, adapterFactory,
                new DeviceFieldNormalizer(), new DeviceIdentityPayloadValidator(),
                Clock.fixed(Instant.parse("2026-09-01T10:00:00Z"), ZoneOffset.UTC),
                entityManager);
    }

    @Test
    void preloadsDeviceAndFacetRowsOnceForTheWholePage() {
        DeviceIdentityPayload payload = payload("device-1");
        IotDevice device = IotDevice.builder().id(100L).sourceDeviceId("device-1").build();
        IotDeviceEndpointPosture posture = IotDeviceEndpointPosture.builder()
                .deviceId(100L).build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(adapterFactory.getAdapter(DeviceSourceProvider.INTUNE)).thenReturn(adapter);
        when(deviceRepository.findBySourceDeviceIdsIncludingArchived(
                10L, List.of("device-1"))).thenReturn(List.of(device));
        when(postureRepository.findByDeviceIdIn(List.of(100L))).thenReturn(List.of(posture));
        when(connectedThingRepository.findByDeviceIdIn(List.of(100L))).thenReturn(List.of());
        when(upsertService.upsertOne(eq(42L), eq(source), eq(adapter), eq(payload),
                eq(device), eq(Map.of(100L, posture)), eq(Map.of()), any(),
                eq(ActorSource.AGENT), eq("corr-1")))
                .thenReturn(DeviceUpsertResult.ok("device-1", "dev-1", UpsertOutcome.UNCHANGED));

        var result = service.upsertBatch(42L,
                new IdentityRegistrationRequest("source-1", "sync-1", List.of(payload)),
                ActorSource.AGENT, "corr-1");

        assertThat(result.unchanged()).isEqualTo(1);
        verify(deviceRepository).findBySourceDeviceIdsIncludingArchived(
                10L, List.of("device-1"));
        verify(postureRepository).findByDeviceIdIn(List.of(100L));
        verify(connectedThingRepository).findByDeviceIdIn(List.of(100L));
    }

    @Test
    void duplicateSourceIdIsRejectedWithoutASecondWrite() {
        DeviceIdentityPayload payload = payload("device-1");
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(adapterFactory.getAdapter(DeviceSourceProvider.INTUNE)).thenReturn(adapter);
        when(deviceRepository.findBySourceDeviceIdsIncludingArchived(
                10L, List.of("device-1"))).thenReturn(List.of());
        when(upsertService.upsertOne(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(DeviceUpsertResult.ok("device-1", "dev-1", UpsertOutcome.CREATED));

        var result = service.upsertBatch(42L,
                new IdentityRegistrationRequest("source-1", "sync-1", List.of(payload, payload)),
                ActorSource.AGENT, "corr-1");

        assertThat(result.created()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(1);
        assertThat(result.results().get(1).error()).contains("duplicated");
        verify(upsertService, times(1)).upsertOne(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void malformedDeviceDoesNotPreventAValidDeviceFromBeingApplied() {
        DeviceIdentityPayload valid = payload("device-1");
        DeviceIdentityPayload overlong = payload("x".repeat(501));
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(adapterFactory.getAdapter(DeviceSourceProvider.INTUNE)).thenReturn(adapter);
        when(deviceRepository.findBySourceDeviceIdsIncludingArchived(
                eq(10L), any())).thenReturn(List.of());
        when(upsertService.upsertOne(any(), any(), any(), eq(valid), any(), any(), any(),
                any(), any(), any()))
                .thenReturn(DeviceUpsertResult.ok("device-1", "dev-1", UpsertOutcome.CREATED));

        var result = service.upsertBatch(42L,
                new IdentityRegistrationRequest("source-1", "sync-1", List.of(valid, overlong)),
                ActorSource.AGENT, "corr-1");

        assertThat(result.created()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(1);
        assertThat(result.results().get(1).error()).contains("externalId exceeds 500");
        verify(upsertService, times(1)).upsertOne(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void orphaningContinuesInIndependentBoundedBatches() {
        when(orphanBatchService.markNextBatch(eq(10L), eq(Instant.parse("2026-09-01T09:00:00Z")
                .atOffset(ZoneOffset.UTC)), any(), eq("corr-1"))).thenReturn(500, 500, 7);

        int orphaned = service.markOrphans(source,
                Instant.parse("2026-09-01T09:00:00Z").atOffset(ZoneOffset.UTC), "corr-1");

        assertThat(orphaned).isEqualTo(1007);
        // The timestamp is stamped on every rebound link and its audit event, so it has to be a
        // real clock reading rather than whatever any() would also accept.
        verify(orphanBatchService, times(3)).markNextBatch(
                eq(10L), any(), eq(Instant.parse("2026-09-01T10:00:00Z").atOffset(ZoneOffset.UTC)),
                eq("corr-1"));
    }

    @Test
    void devicePageCommitsBeforeTheHandlerStartsOrphanDetection() throws Exception {
        Method method = IotIdentityRegistrationService.class.getMethod(
                "upsertBatch", Long.class, IdentityRegistrationRequest.class,
                ActorSource.class, String.class);

        assertThat(method.getAnnotation(Transactional.class).propagation())
                .isEqualTo(Propagation.REQUIRES_NEW);
    }

    private static DeviceIdentityPayload payload(String externalId) {
        return new DeviceIdentityPayload(
                externalId, null, null, null, "device", null, "macOS", null,
                "Apple", "Mac", null, null, null, null, null, "COMPANY",
                "compliant", null, "mdm", null, null, null, null,
                null, null, null, null, null, Map.of());
    }
}
