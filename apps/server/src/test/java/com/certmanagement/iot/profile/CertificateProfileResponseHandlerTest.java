// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceEvent;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.certificate.IotCertificateProfileCorrelationService;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceEventRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CertificateProfileResponseHandlerTest {
    @Mock private CertificateProfileRepository profileRepository;
    @Mock private CertificateProfileConfigurationRepository configurationRepository;
    @Mock private CertificateProfileProviderSnapshotRepository snapshotRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceEventRepository eventRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private IotCertificateProfileCorrelationService certificateProfileCorrelationService;

    private CertificateProfileResponseHandler handler;
    private CertificateProfileJsonCodec jsonCodec;

    @BeforeEach
    void setUp() {
        jsonCodec = new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build());
        handler = new CertificateProfileResponseHandler(
                profileRepository, configurationRepository, snapshotRepository,
                sourceRepository, eventRepository, eventService,
                certificateProfileCorrelationService,
                jsonCodec,
                new IotDeviceProperties(),
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void staleOperationResponseCannotOverwriteNewerDesiredRevision() {
        IotDeviceSource source = source();
        CertificateProfile profile = CertificateProfile.builder()
                .id(100L).profileXref("profile-1").organizationId(42L).deviceSourceId(10L)
                .latestOperationXref("operation-new").desiredRevision(3L)
                .providerSyncStatus(ProviderSyncStatus.PENDING)
                .build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));

        handler.handleOperation(CertificateProfileOperationResponse.builder()
                .organizationId("42").sourceXref("source-1").profileXref("profile-1")
                .operationXref("operation-old").desiredRevision(2L).status("SUCCEEDED")
                .build());

        verify(profileRepository, never()).save(any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void completionArrivingBeforeItsPartFinalizesAfterPartIsRecorded() {
        IotDeviceSource source = source();
        AtomicBoolean partRecorded = new AtomicBoolean();
        IotDeviceSourceEvent completionEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"status\":\"SUCCEEDED\",\"totalProfiles\":1,\"totalBatches\":1}")
                .build();
        IotDeviceSourceEvent partEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"batchIndex\":0,\"profileCount\":1}").build();
        ProfileObservedState observed = observed("native-1", "2026-08-24T23:59:59Z");
        CertificateProfile existingProfile = observedOnlyProfile();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-1");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(10L, "sync-1:part:0"))
                .thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, existingProfile.getProviderProfileType(), "native-1"))
                .thenReturn(Optional.of(existingProfile));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-1", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of(completionEvent));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-1", DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED))
                .thenAnswer(invocation -> partRecorded.get() ? List.of(partEvent) : List.of());
        doAnswer(invocation -> {
            if (invocation.getArgument(1) == DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED) {
                partRecorded.set(true);
            }
            return null;
        }).when(eventService).record(any(), any(), any(), any(), any(), any(), any());

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-1")
                .status("SUCCEEDED").totalProfiles(1).totalBatches(1)
                .completedAt("2026-08-24T23:59:59Z").build());
        verify(eventService, never()).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_COMPLETED), any(), any(), any(), any(), any());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-1")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(List.of(observed)))
                .profiles(List.of(observed)).respondedAt("2026-08-24T23:59:59Z").build());

        verify(eventService).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED), eq("RECEIVED"),
                any(), eq(OffsetDateTime.parse("2026-08-24T23:59:59Z")),
                eq("sync-1"), eq("sync-1:part:0"));
        verify(eventService).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_COMPLETED), eq("SUCCEEDED"),
                any(), any(), eq("sync-1"), eq("sync-1:completed"));
    }

    @Test
    void completedDiscoveryAppliesValidatedCertificateCorrelations() {
        IotDeviceSource source = source();
        IotDeviceSourceEvent completionEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"status\":\"SUCCEEDED\",\"totalProfiles\":0,"
                        + "\"totalBatches\":0,\"certificateCorrelations\":[{"
                        + "\"certificateXref\":\"cert_1\",\"status\":\"MATCHED\","
                        + "\"providerProfileId\":\"native-1\","
                        + "\"providerProfileType\":"
                        + "\"#microsoft.graph.macOSScepCertificateProfile\","
                        + "\"matchMethod\":\"SHA1\"}]}")
                .build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-correlation");
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-correlation", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of(completionEvent));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-correlation", DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED))
                .thenReturn(List.of());

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-correlation")
                .status("SUCCEEDED").totalProfiles(0).totalBatches(0)
                .certificateCorrelations(List.of(new CertificateCorrelationResult(
                        "cert_1", "MATCHED", "native-1",
                        "#microsoft.graph.macOSScepCertificateProfile", "SHA1")))
                .completedAt("2026-08-24T23:59:59Z").build());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CertificateCorrelationResult>> results =
                ArgumentCaptor.forClass(List.class);
        verify(certificateProfileCorrelationService).reconcile(
                eq(source), eq("sync-correlation"), results.capture(), any());
        assertThat(results.getValue()).singleElement().satisfies(result -> {
            assertThat(result.certificateXref()).isEqualTo("cert_1");
            assertThat(result.providerProfileId()).isEqualTo("native-1");
            assertThat(result.matchMethod()).isEqualTo("SHA1");
        });
        verify(profileRepository).markMissingFromCompletedSync(
                10L, "sync-correlation",
                "Profile was not returned by the latest Intune sync",
                OffsetDateTime.parse("2026-08-25T00:00:00Z"));
    }

    @Test
    void completedEmptyInventoryMarksPreviouslyKnownProfilesNotFound() {
        IotDeviceSource source = source();
        IotDeviceSourceEvent completionEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"status\":\"SUCCEEDED\",\"totalProfiles\":0,\"totalBatches\":0}")
                .build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-empty");
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-empty", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of(completionEvent));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-empty", DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED))
                .thenReturn(List.of());
        when(profileRepository.markMissingFromCompletedSync(
                eq(10L), eq("sync-empty"), any(), any())).thenReturn(2);

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-empty")
                .status("SUCCEEDED").totalProfiles(0).totalBatches(0)
                .completedAt("2026-08-24T23:59:59Z").build());

        verify(profileRepository).markMissingFromCompletedSync(
                10L, "sync-empty",
                "Profile was not returned by the latest Intune sync",
                OffsetDateTime.parse("2026-08-25T00:00:00Z"));
        verify(eventService).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_COMPLETED), eq("SUCCEEDED"),
                argThat(detail -> Integer.valueOf(2).equals(detail.get("missingProfileCount"))),
                any(), eq("sync-empty"), eq("sync-empty:completed"));
    }

    @Test
    void duplicateBatchIndexesCannotSatisfyCompletionTotals() {
        IotDeviceSource source = source();
        IotDeviceSourceEvent completionEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"status\":\"SUCCEEDED\",\"totalProfiles\":2,\"totalBatches\":2}")
                .build();
        IotDeviceSourceEvent first = IotDeviceSourceEvent.builder()
                .detailJson("{\"batchIndex\":0,\"profileCount\":1}").build();
        IotDeviceSourceEvent duplicate = IotDeviceSourceEvent.builder()
                .detailJson("{\"batchIndex\":0,\"profileCount\":1}").build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-2");
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-2", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of(completionEvent));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-2", DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED))
                .thenReturn(List.of(first, duplicate));

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-2")
                .status("SUCCEEDED").totalProfiles(2).totalBatches(2)
                .completedAt("2026-08-24T23:59:59Z").build());

        verify(eventService, never()).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_COMPLETED), any(), any(), any(), any(), any());
        // The marking UPDATE runs before the completion event, so asserting only that the event is
        // absent would still pass if it were hoisted above the completeness guard. A sync that did
        // not prove it saw everything must never mass-mark a source's profiles missing.
        verify(profileRepository, never()).markMissingFromCompletedSync(
                any(), any(), any(), any());
    }

    @Test
    void operationSuccessWithDifferentAuthoritativeConfigurationBecomesDrifted() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        ProfileObservedState observed = managedObserved("native-1", 4096,
                "2026-08-24T23:59:59Z");
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());
        when(configurationRepository.findById(100L))
                .thenReturn(Optional.of(desiredConfiguration()));

        handler.handleOperation(CertificateProfileOperationResponse.builder()
                .organizationId("42").sourceXref("source-1").profileXref("profile-1")
                .operationXref("operation-1").desiredRevision(2L).status("SUCCEEDED")
                .profile(observed).respondedAt("2026-08-24T23:59:59Z").build());

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.DRIFTED);
        assertThat(profile.getAppliedRevision()).isNull();
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_DRIFTED),
                eq("DRIFTED"), any(), any(), eq("operation-1"),
                eq("profile-drifted:profile-1:2"));
    }

    @Test
    void operationResponseOlderThanSnapshotCannotOverwriteAggregateState() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        profile.setProviderSyncStatus(ProviderSyncStatus.DRIFTED);
        CertificateProfileProviderSnapshot newer = CertificateProfileProviderSnapshot.builder()
                .profileId(100L)
                .providerObservedAt(java.time.OffsetDateTime.parse("2026-08-24T23:59:59Z"))
                .build();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.of(newer));

        handler.handleOperation(CertificateProfileOperationResponse.builder()
                .organizationId("42").sourceXref("source-1").profileXref("profile-1")
                .operationXref("operation-1").desiredRevision(2L).status("FAILED")
                .respondedAt("2026-08-24T23:59:58Z").build());

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.DRIFTED);
        verify(profileRepository, never()).save(any());
    }

    @Test
    void matchingDiscoveryRecoversPendingOperationAndIgnoresListOrder() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        ProfileObservedState observed = managedObserved("native-1", 2048,
                "2026-08-24T23:59:59Z");
        List<ProfileObservedState> profiles = List.of(observed);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-recover");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(10L, "sync-recover:part:0"))
                .thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, profile.getProviderProfileType(), "native-1"))
                .thenReturn(Optional.of(profile));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());
        when(configurationRepository.findById(100L))
                .thenReturn(Optional.of(desiredConfiguration()));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-recover", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-recover")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(profiles)).profiles(profiles)
                .respondedAt("2026-08-24T23:59:59Z").build());

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.IN_SYNC);
        assertThat(profile.getAppliedRevision()).isEqualTo(2L);
        assertThat(profile.getLastProviderSyncXref()).isEqualTo("sync-recover");
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_APPLY_SUCCEEDED),
                eq("IN_SYNC"), any(), any(), eq("operation-1"), eq("operation-1:succeeded"));
    }

    @Test
    void malformedObservationDoesNotRollbackValidSiblingAndFailsRun() {
        IotDeviceSource source = source();
        CertificateProfile existing = observedOnlyProfile();
        ProfileObservedState valid = observed("native-1", "2026-08-24T23:59:59Z");
        ProfileObservedState future = observed("native-2", "2099-01-01T00:00:00Z");
        List<ProfileObservedState> profiles = List.of(valid, future);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-malformed");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(10L, "sync-malformed:part:0"))
                .thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, existing.getProviderProfileType(), "native-1"))
                .thenReturn(Optional.of(existing));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-malformed")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(profiles)).profiles(profiles)
                .respondedAt("2026-08-24T23:59:59Z").build());

        verify(profileRepository).save(existing);
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-malformed"),
                eq("sync-malformed:failed"));
    }

    @Test
    void oversizedObservedConfigurationDoesNotRollbackValidSiblingOrTriggerRedelivery() {
        IotDeviceSource source = source();
        CertificateProfile existing = observedOnlyProfile();
        ProfileObservedState valid = observed("native-1", "2026-08-24T23:59:59Z");
        ProfileObservedState oversized = observed("native-oversized", "2026-08-24T23:59:59Z");
        oversized.setConfiguration(Map.of(
                "providerConfig", Map.of("providerMetadata", "x".repeat(70 * 1024))));
        List<ProfileObservedState> profiles = List.of(valid, oversized);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-oversized");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(
                10L, "sync-oversized:part:0")).thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, existing.getProviderProfileType(), "native-1"))
                .thenReturn(Optional.of(existing));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-oversized")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(profiles)).profiles(profiles)
                .respondedAt("2026-08-24T23:59:59Z").build());

        verify(profileRepository).save(existing);
        verify(profileRepository, never())
                .findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                        10L, existing.getProviderProfileType(), "native-oversized");
        verify(eventService).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED), eq("RECEIVED"),
                argThat(detail -> Integer.valueOf(1).equals(detail.get("profileCount"))
                        && Integer.valueOf(1).equals(detail.get("rejectedProfileCount"))),
                any(), eq("sync-oversized"), eq("sync-oversized:part:0"));
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), argThat(detail ->
                        "INVALID_PROFILE_OBSERVATION".equals(detail.get("errorCode"))
                                && detail.get("errorMessage").toString()
                                .contains("Profile JSON exceeds 64 KiB")
                                && detail.get("errorMessage").toString().length() <= 500),
                any(), eq("sync-oversized"), eq("sync-oversized:failed"));
    }

    @Test
    void nullObservationDoesNotPoisonValidSiblingOrTriggerRedelivery() {
        IotDeviceSource source = source();
        CertificateProfile existing = observedOnlyProfile();
        ProfileObservedState valid = observed("native-1", "2026-08-24T23:59:59Z");
        List<ProfileObservedState> profiles = Arrays.asList(valid, null);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-null-profile");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(
                10L, "sync-null-profile:part:0")).thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, existing.getProviderProfileType(), "native-1"))
                .thenReturn(Optional.of(existing));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-null-profile")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(profiles)).profiles(profiles)
                .respondedAt("2026-08-24T23:59:59Z").build());

        verify(profileRepository).save(existing);
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-null-profile"),
                eq("sync-null-profile:failed"));
    }

    @Test
    void futureOperationTimestampFailsCurrentOperationWithoutBrokerRedelivery() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));

        handler.handleOperation(CertificateProfileOperationResponse.builder()
                .organizationId("42").sourceXref("source-1").profileXref("profile-1")
                .operationXref("operation-1").desiredRevision(2L).status("FAILED")
                .respondedAt("2099-01-01T00:00:00Z").build());

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.FAILED);
        assertThat(profile.getProviderSyncError())
                .contains("PROFILE_RESPONSE_TIMESTAMP_INVALID", "clock skew");
        verify(profileRepository).save(profile);
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_APPLY_FAILED),
                eq("FAILED"), any(), any(), any(), eq("operation-1:failed"));
    }

    @Test
    void malformedDuplicateCannotRegressTerminalOperation() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        profile.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
        profile.setLatestOperationCompletedAt(
                OffsetDateTime.parse("2026-08-24T23:59:30Z"));
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));

        handler.handleOperation(CertificateProfileOperationResponse.builder()
                .organizationId("42").sourceXref("source-1").profileXref("profile-1")
                .operationXref("operation-1").desiredRevision(2L).status("FAILED")
                .respondedAt("2099-01-01T00:00:00Z").build());

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.IN_SYNC);
        verify(profileRepository, never()).save(any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void malformedPartMetadataFailsRunWithoutThrowing() {
        IotDeviceSource source = source();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-invalid-part");

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-invalid-part")
                .batchIndex(-1).batchChecksum("not-a-checksum")
                .profiles(List.of(observed("native-1", "2026-08-24T23:59:59Z"))).build());

        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-invalid-part"),
                eq("sync-invalid-part:failed"));
    }

    @Test
    void futurePartTimestampFailsRunBeforePersistingProfiles() {
        IotDeviceSource source = source();
        ProfileObservedState observed = observed("native-1", "2026-08-24T23:59:59Z");
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-future-part");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(
                10L, "sync-future-part:part:0")).thenReturn(Optional.empty());

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-future-part")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(List.of(observed)))
                .profiles(List.of(observed)).respondedAt("2099-01-01T00:00:00Z").build());

        verify(profileRepository, never())
                .findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(any(), any(), any());
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), argThat(detail ->
                        "PROFILE_SYNC_TIMESTAMP_INVALID".equals(detail.get("errorCode"))
                                && detail.get("errorMessage").toString().contains("clock skew")),
                any(), eq("sync-future-part"),
                eq("sync-future-part:failed"));
    }

    @Test
    void futureCompletionTimestampFailsRunWithoutThrowing() {
        IotDeviceSource source = source();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-future-completion");

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1")
                .requestId("sync-future-completion").status("SUCCEEDED")
                .totalProfiles(0).totalBatches(0)
                .completedAt("2099-01-01T00:00:00Z").build());

        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-future-completion"),
                eq("sync-future-completion:failed"));
    }

    @Test
    void duplicateChecksumsAreComparedCaseInsensitively() {
        IotDeviceSource source = source();
        ProfileObservedState observed = observed("native-1", "2026-08-24T23:59:59Z");
        String checksum = jsonCodec.sha256(List.of(observed));
        IotDeviceSourceEvent storedPart = IotDeviceSourceEvent.builder()
                .detailJson("{\"batchChecksum\":\"" + checksum.toLowerCase() + "\"}")
                .build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-checksum-case");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(
                10L, "sync-checksum-case:part:0")).thenReturn(Optional.of(storedPart));

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-checksum-case")
                .batchIndex(0).batchChecksum(checksum.toUpperCase())
                .profiles(List.of(observed)).build());

        verify(eventService, never()).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_FAILED), any(), any(), any(), any(), any());
    }

    @Test
    void agentErrorFailsExactPendingOperationAndRedactsSensitiveDetail() {
        IotDeviceSource source = source();
        CertificateProfile profile = managedPendingProfile();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByLatestOperation("operation-1", 42L, 10L))
                .thenReturn(Optional.of(profile));

        handler.handleOperationAgentError(
                "source-1", 42L, "operation-1", "intune_profile_create_failed",
                "client_secret=hunter2 Authorization: Bearer header.payload.signature\nGraph rejected",
                "2026-08-24T23:59:59Z");

        assertThat(profile.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.FAILED);
        assertThat(profile.getLatestOperationCompletedAt())
                .isEqualTo(OffsetDateTime.parse("2026-08-25T00:00:00Z"));
        assertThat(profile.getProviderSyncError())
                .contains("INTUNE_PROFILE_CREATE_FAILED", "[REDACTED]", "Graph rejected")
                .doesNotContain("hunter2", "header.payload.signature")
                .hasSizeLessThanOrEqualTo(1000);
        verify(profileRepository).save(profile);
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_APPLY_FAILED),
                eq("FAILED"), argThat(detail ->
                        "INTUNE_PROFILE_CREATE_FAILED".equals(detail.get("errorCode"))
                                && !detail.get("errorMessage").toString().contains("hunter2")
                                && detail.get("errorMessage").toString().length() <= 500),
                eq(OffsetDateTime.parse("2026-08-24T23:59:59Z")), eq("operation-1"),
                eq("operation-1:failed"));
    }

    @Test
    void staleOrTerminalOperationAgentErrorCannotRegressProfile() {
        IotDeviceSource source = source();
        CertificateProfile terminal = managedPendingProfile();
        terminal.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
        terminal.setLatestOperationCompletedAt(
                OffsetDateTime.parse("2026-08-24T23:59:30Z"));
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByLatestOperation("operation-1", 42L, 10L))
                .thenReturn(Optional.of(terminal));

        handler.handleOperationAgentError(
                "source-1", 42L, "operation-1", "FAILED", "late failure",
                "2026-08-24T23:59:59Z");

        assertThat(terminal.getProviderSyncStatus()).isEqualTo(ProviderSyncStatus.IN_SYNC);
        verify(profileRepository, never()).save(any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void agentErrorFailsOnlyOpenCmsIssuedProfileSyncRun() {
        IotDeviceSource source = source();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("profile_sync_123");

        handler.handleSyncAgentError(
                "source-1", 42L, "profile_sync_123", "PROFILE_LIST_FAILED",
                "password=top-secret Graph unavailable", "2099-01-01T00:00:00Z");

        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), argThat(detail ->
                        "PROFILE_LIST_FAILED".equals(detail.get("errorCode"))
                                && detail.get("errorMessage").toString().contains("[REDACTED]")
                                && !detail.get("errorMessage").toString().contains("top-secret")),
                eq(OffsetDateTime.parse("2026-08-25T00:00:00Z")), eq("profile_sync_123"),
                eq("profile_sync_123:failed"));
    }

    @Test
    void unknownProfileAgentErrorCorrelationsAreIgnored() {
        IotDeviceSource source = source();
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        when(profileRepository.lockByLatestOperation("unknown-operation", 42L, 10L))
                .thenReturn(Optional.empty());

        handler.handleOperationAgentError(
                "source-1", 42L, "unknown-operation", "FAILED", "unknown operation",
                "2026-08-24T23:59:59Z");
        handler.handleSyncAgentError(
                "source-1", 42L, "unknown-sync", "FAILED", "unknown sync",
                "2026-08-24T23:59:59Z");

        verify(profileRepository, never()).save(any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void completionWithProfileCountMismatchFailsInsteadOfCompleting() {
        IotDeviceSource source = source();
        IotDeviceSourceEvent completionEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"status\":\"SUCCEEDED\",\"totalProfiles\":2,\"totalBatches\":1}")
                .build();
        IotDeviceSourceEvent partEvent = IotDeviceSourceEvent.builder()
                .detailJson("{\"batchIndex\":0,\"profileCount\":1}").build();
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-counts");
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-counts", DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED))
                .thenReturn(List.of(completionEvent));
        when(eventRepository.findByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, "sync-counts", DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED))
                .thenReturn(List.of(partEvent));

        handler.handleComplete(CertificateProfileSyncResponseComplete.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-counts")
                .status("SUCCEEDED").totalProfiles(2).totalBatches(1)
                .completedAt("2026-08-24T23:59:59Z").build());

        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-counts"), eq("sync-counts:failed"));
        verify(eventService, never()).record(eq(source),
                eq(DeviceSourceEventType.PROFILE_SYNC_COMPLETED), any(), any(), any(), any(), any());
        // The marking UPDATE runs before the completion event, so asserting only that the event is
        // absent would still pass if it were hoisted above the completeness guard. A sync that did
        // not prove it saw everything must never mass-mark a source's profiles missing.
        verify(profileRepository, never()).markMissingFromCompletedSync(
                any(), any(), any(), any());
    }

    @Test
    void responseWithoutCmsIssuedRequestIsIgnored() {
        IotDeviceSource source = source();
        ProfileObservedState observed = observed("native-1", "2026-08-24T23:59:59Z");
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-unknown")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(List.of(observed)))
                .profiles(List.of(observed)).build());

        verify(profileRepository, never())
                .findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(any(), any(), any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void markerOnDraftProfileCannotBindProviderIdentity() {
        IotDeviceSource source = source();
        CertificateProfile draft = managedPendingProfile();
        draft.setLifecycleStatus(ProfileLifecycleStatus.DRAFT);
        draft.setProviderProfileId(null);
        ProfileObservedState observed = managedObserved("native-other", 2048,
                "2026-08-24T23:59:59Z");
        List<ProfileObservedState> profiles = List.of(observed);
        when(sourceRepository.lockBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source));
        allowOpenRequest("sync-marker");
        when(eventRepository.findByDeviceSourceIdAndDedupeKey(10L, "sync-marker:part:0"))
                .thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                10L, draft.getProviderProfileType(), "native-other"))
                .thenReturn(Optional.empty());
        when(profileRepository.findByDeviceSourceIdAndProviderCorrelationMarker(
                10L, "certping:profile-1")).thenReturn(Optional.of(draft));

        handler.handlePart(CertificateProfileSyncResponsePart.builder()
                .organizationId("42").sourceXref("source-1").requestId("sync-marker")
                .batchIndex(0).batchChecksum(jsonCodec.sha256(profiles)).profiles(profiles)
                .respondedAt("2026-08-24T23:59:59Z").build());

        assertThat(draft.getProviderProfileId()).isNull();
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_SYNC_FAILED),
                eq("FAILED"), any(), any(), eq("sync-marker"), eq("sync-marker:failed"));
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .displayName("Primary Intune").build();
    }

    private void allowOpenRequest(String requestXref) {
        when(eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                10L, requestXref, DeviceSourceEventType.PROFILE_SYNC_REQUESTED))
                .thenReturn(true);
    }

    private static ProfileObservedState observed(String providerId, String observedAt) {
        return ProfileObservedState.builder()
                .providerProfileId(providerId)
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .name("Observed")
                .targetPlatform("WINDOWS")
                .targetVariant("STANDARD")
                .profileKind("CERTIFICATE_ENROLLMENT")
                .enrollmentMethod("SCEP")
                .configuration(Map.of())
                .providerResponse(Map.of("id", providerId))
                .observedAt(observedAt)
                .build();
    }

    private static CertificateProfile observedOnlyProfile() {
        return CertificateProfile.builder()
                .id(100L).profileXref("profile-1").organizationId(42L).deviceSourceId(10L)
                .name("Observed").targetPlatform("WINDOWS").targetVariant("STANDARD")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerProfileId("native-1").lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                .profileOrigin(ProfileOrigin.PROVIDER_DISCOVERED)
                .controlMode(ProfileControlMode.OBSERVED_ONLY)
                .profileKind(ProfileKind.CERTIFICATE_ENROLLMENT).enrollmentMethod("SCEP")
                .providerSyncStatus(ProviderSyncStatus.IN_SYNC).build();
    }

    private static CertificateProfile managedPendingProfile() {
        return CertificateProfile.builder()
                .id(100L).profileXref("profile-1").organizationId(42L).deviceSourceId(10L)
                .name("Managed").targetPlatform("WINDOWS").targetVariant("STANDARD")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerProfileId("native-1").providerCorrelationMarker("certping:profile-1")
                .lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                .profileOrigin(ProfileOrigin.CMS_CREATED).controlMode(ProfileControlMode.CMS_MANAGED)
                .profileKind(ProfileKind.CERTIFICATE_ENROLLMENT).enrollmentMethod("SCEP")
                .desiredRevision(2L).latestOperationXref("operation-1")
                .latestOperationStartedAt(java.time.OffsetDateTime.parse("2026-08-24T23:50:00Z"))
                .providerSyncStatus(ProviderSyncStatus.PENDING).build();
    }

    private static CertificateProfileConfiguration desiredConfiguration() {
        return CertificateProfileConfiguration.builder()
                .profileId(100L).organizationId(42L).deviceSourceId(10L)
                .certificateScope("DEVICE").keyAlgorithm("RSA").keySize(2048)
                .signatureHash("SHA2").subjectNameFormat("CN={{AAD_Device_ID}}")
                .subjectAltNameFormatsJson("[{\"type\":\"DNS\",\"format\":\"device.example\"}]")
                .extendedKeyUsagesJson("["
                        + "{\"name\":\"Server Authentication\",\"objectIdentifier\":\"1.3.6.1.5.5.7.3.1\"},"
                        + "{\"name\":\"Client Authentication\",\"objectIdentifier\":\"1.3.6.1.5.5.7.3.2\"}]")
                .keyUsagesJson("[\"digitalSignature\",\"keyEncipherment\"]")
                .validityValue(12).validityUnit("MONTHS")
                .providerConfigJson("{\"renewalThresholdPercentage\":20,"
                        + "\"keyStorageProvider\":\"useSoftwareKsp\"}")
                .build();
    }

    private static ProfileObservedState managedObserved(
            String providerId, int keySize, String observedAt) {
        Map<String, Object> configuration = new java.util.LinkedHashMap<>();
        configuration.put("certificateScope", "DEVICE");
        configuration.put("keyAlgorithm", "RSA");
        configuration.put("keySize", keySize);
        configuration.put("signatureHash", "SHA2");
        configuration.put("subjectNameFormat", "CN={{AAD_Device_ID}}");
        configuration.put("subjectAltNameFormats", List.of(
                Map.of("type", "dnsName", "format", "device.example")));
        configuration.put("extendedKeyUsages", List.of(
                Map.of("name", "Client Authentication",
                        "objectIdentifier", "1.3.6.1.5.5.7.3.2"),
                Map.of("name", "Server Authentication",
                        "objectIdentifier", "1.3.6.1.5.5.7.3.1")));
        configuration.put("keyUsages", List.of("keyEncipherment", "digitalSignature"));
        configuration.put("validityValue", 12);
        configuration.put("validityUnit", "MONTHS");
        configuration.put("providerConfig", Map.of(
                "renewalThresholdPercentage", 20,
                "keyStorageProvider", "useSoftwareKsp"));
        return ProfileObservedState.builder()
                .providerProfileId(providerId)
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:profile-1")
                .name("Managed").targetPlatform("WINDOWS").targetVariant("STANDARD")
                .profileKind("CERTIFICATE_ENROLLMENT").enrollmentMethod("SCEP")
                .configuration(configuration).providerResponse(Map.of("id", providerId))
                .observedAt(observedAt).build();
    }
}
