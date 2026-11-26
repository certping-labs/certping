// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileConfigurationRepository;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Source-first ingestion: a certificate persists when organization + device source are known,
 * profile and device links are added only from deterministic evidence, and hints that provably
 * belong elsewhere reject the message.
 */
@ExtendWith(MockitoExtension.class)
class IotCertificateIngestionServiceTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-26T12:00:00Z"), ZoneOffset.UTC);
    private static final long ORG = 42L;
    private static final long SOURCE_ID = 9L;
    private static final String SOURCE_REF = "intune-primary";

    @Mock private OrganizationRepository organizationRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private CertificateProfileRepository profileRepository;
    @Mock private CertificateProfileConfigurationRepository configurationRepository;
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotCertificateEnrollmentRepository enrollmentRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private FeatureFlagService featureFlagService;
    @Mock private IotAlertPublisher alertPublisher;
    @Mock private IotAuditRecorder iotAudit;

    @BeforeEach
    void enableFeature() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null))
                .thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, ORG))
                .thenReturn(true);
        lenient().when(organizationRepository.existsById(ORG)).thenReturn(true);
    }

    private IotDeviceSource stubSource() {
        IotDeviceSource source = IotDeviceSource.builder()
                .id(SOURCE_ID).organizationId(ORG).sourceXref("src_1")
                .connectionProfileRef(SOURCE_REF).build();
        when(sourceRepository.findByOrganizationIdAndConnectionProfileRef(ORG, SOURCE_REF))
                .thenReturn(Optional.of(source));
        return source;
    }

    private void stubEnrollmentSave() {
        when(enrollmentRepository.save(any())).thenAnswer(invocation -> {
            IotCertificateEnrollment row = invocation.getArgument(0);
            if (row.getId() == null) row.setId(101L);
            return row;
        });
    }

    private void stubNoExistingEnrollment() {
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                ORG, SOURCE_ID, "tx-1")).thenReturn(Optional.empty());
    }

    // ---- the highlighted failure mode: profile not synchronized yet -----------------------------

    @Test
    void certificateIsStoredWithNullProfileWhenNoProfileIsKnown() {
        // An Intune-only profile that CertPing has never synchronized must not lose the
        // certificate: the enrollment persists under the source with profile_id = NULL.
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service().handle(validMessage());

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst()).satisfies(row -> {
            assertThat(row.getProfileId()).isNull();
            assertThat(row.getProfileResolutionStatus()).isEqualTo("PENDING_SYNC");
            assertThat(row.getDeviceSourceId()).isEqualTo(SOURCE_ID);
        });
        ArgumentCaptor<IotDeviceCertificate> certificate =
                ArgumentCaptor.forClass(IotDeviceCertificate.class);
        verify(certificateRepository).save(certificate.capture());
        assertThat(certificate.getValue()).satisfies(row -> {
            assertThat(row.getProfileId()).isNull();
            assertThat(row.getDeviceSourceId()).isEqualTo(SOURCE_ID);
            assertThat(row.getIssuerXref()).isNull();
            assertThat(row.getCertificateScope()).isNull();
            assertThat(row.getFingerprintSha1()).isEqualTo("ef".repeat(20));
            assertThat(row.getFingerprintSha256()).isEqualTo("ab".repeat(32));
        });
        // The unresolved profile is auditable, not silent.
        verify(eventService).recordEnrollment(any(),
                eq(DeviceEventType.CERTIFICATE_PROFILE_UNMATCHED), eq("PENDING_SYNC"),
                any(), any(), any(), any(), any());
    }

    @Test
    void provenProfileHintLinksProfileAndConfiguration() {
        IotDeviceSource source = stubSource();
        CertificateProfile profile = CertificateProfile.builder()
                .id(7L).profileXref("profile-1").organizationId(ORG)
                .deviceSourceId(source.getId()).build();
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", ORG))
                .thenReturn(Optional.of(profile));
        when(configurationRepository.findById(7L)).thenReturn(Optional.of(
                CertificateProfileConfiguration.builder()
                        .profileId(7L).issuerXref("ManagementCA").certificateScope("DEVICE").build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setProfileXref("profile-1");
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getProfileId()).isEqualTo(7L);
        assertThat(enrollment.getAllValues().getFirst().getProfileResolutionStatus())
                .isEqualTo("MATCHED");
        ArgumentCaptor<IotDeviceCertificate> certificate =
                ArgumentCaptor.forClass(IotDeviceCertificate.class);
        verify(certificateRepository).save(certificate.capture());
        assertThat(certificate.getValue().getCertificateScope()).isEqualTo("DEVICE");
        assertThat(certificate.getValue().getIssuerXref()).isEqualTo("ManagementCA");
        verify(eventService).recordEnrollment(any(),
                eq(DeviceEventType.CERTIFICATE_PROFILE_MATCHED), eq("MATCHED"),
                any(), any(), any(), any(), any());
    }

    @Test
    void profileHintBelongingToAnotherSourceRejectsTheMessage() {
        stubSource();
        CertificateProfile foreignProfile = CertificateProfile.builder()
                .id(7L).profileXref("profile-1").organizationId(ORG)
                .deviceSourceId(8L).build();   // different source
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", ORG))
                .thenReturn(Optional.of(foreignProfile));

        ScepCertificateIssuedMessage message = validMessage();
        message.setProfileXref("profile-1");
        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void unknownProfileHintKeepsTheCertificateAsPendingSync() {
        stubSource();
        when(profileRepository.lockByProfileXrefAndOrganizationId("not-synced-yet", ORG))
                .thenReturn(Optional.empty());
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setProfileXref("not-synced-yet");
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getProfileId()).isNull();
        assertThat(enrollment.getAllValues().getFirst().getProfileResolutionStatus())
                .isEqualTo("PENDING_SYNC");
        verify(certificateRepository).save(any());
    }

    @Test
    void singleProviderProfileIdHintLinksTheSourceProfile() {
        IotDeviceSource source = stubSource();
        when(profileRepository.findAllByDeviceSourceIdAndProviderProfileId(SOURCE_ID, "graph-1"))
                .thenReturn(List.of(CertificateProfile.builder()
                        .id(7L).profileXref("profile-1").organizationId(ORG)
                        .deviceSourceId(source.getId()).build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setProviderProfileId("graph-1");
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getProfileId()).isEqualTo(7L);
        assertThat(enrollment.getAllValues().getFirst().getProfileResolutionStatus())
                .isEqualTo("MATCHED");
    }

    @Test
    void ambiguousProviderProfileIdHintNeverPicksARow() {
        stubSource();
        when(profileRepository.findAllByDeviceSourceIdAndProviderProfileId(SOURCE_ID, "graph-1"))
                .thenReturn(List.of(CertificateProfile.builder().id(1L).build(),
                        CertificateProfile.builder().id(2L).build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setProviderProfileId("graph-1");
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getProfileId()).isNull();
        assertThat(enrollment.getAllValues().getFirst().getProfileResolutionStatus())
                .isEqualTo("AMBIGUOUS");
    }

    // ---- source routing ---------------------------------------------------------------------

    @Test
    void unknownSourceDropsTheMessageWithoutWrites() {
        when(sourceRepository.findByOrganizationIdAndConnectionProfileRef(ORG, SOURCE_REF))
                .thenReturn(Optional.empty());

        service().handle(validMessage());

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void mismatchedSourceXrefCorroborationRejectsTheMessage() {
        stubSource();   // sourceXref is src_1

        ScepCertificateIssuedMessage message = validMessage();
        message.setSourceXref("src_other");
        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void aliasRouteKeyStillResolvesTheRealSource() {
        // Through the temporary /scep/v1/default alias the endpointId is 'default' while
        // connectionProfileRef names the real source — routing must use the latter.
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setEndpointId("default");
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst()).satisfies(row -> {
            assertThat(row.getDeviceSourceId()).isEqualTo(SOURCE_ID);
            assertThat(row.getEndpointId()).isEqualTo(SOURCE_REF);
        });
        verify(enrollmentRepository).lockTransaction(SOURCE_ID, "tx-1");
    }

    // ---- device identifier provenance ---------------------------------------------------------

    @Test
    void assertedIdentifierIsStoredButNeverAutoLinksADevice() {
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(identifier("device-guid", "MANAGED_DEVICE_ID", "ASSERTED"));
        service().handle(message);

        // Even if the device exists, an unproven identifier must not be consulted at all.
        verify(deviceRepository, never())
                .findRegisteredBySourceDeviceId(any(), any());
        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst()).satisfies(row -> {
            assertThat(row.getDeviceId()).isNull();
            assertThat(row.getDeviceMatchStatus()).isEqualTo("IDENTIFIER_UNVERIFIED");
            assertThat(row.getSourceIdentifierAssurance()).isEqualTo("ASSERTED");
        });
    }

    @Test
    void validatedManagedDeviceIdentifierLinksTheDevice() {
        stubSource();
        when(deviceRepository.findRegisteredBySourceDeviceId(
                SOURCE_ID, "device-guid")).thenReturn(Optional.of(
                IotDevice.builder().id(11L).organizationId(ORG)
                        .deviceSourceId(SOURCE_ID).sourceDeviceId("device-guid").build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(
                identifier("device-guid", "MANAGED_DEVICE_ID", "MICROSOFT_VALIDATED"));
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceId()).isEqualTo(11L);
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus()).isEqualTo("MATCHED");
        ArgumentCaptor<IotDeviceCertificate> certificate =
                ArgumentCaptor.forClass(IotDeviceCertificate.class);
        verify(certificateRepository).save(certificate.capture());
        assertThat(certificate.getValue().getDeviceId()).isEqualTo(11L);
    }

    @Test
    void validatedIdentifierWithoutASyncedDeviceStaysPendingRelink() {
        stubSource();
        when(deviceRepository.findRegisteredBySourceDeviceId(
                SOURCE_ID, "device-guid")).thenReturn(Optional.empty());
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(
                identifier("device-guid", "MANAGED_DEVICE_ID", "MICROSOFT_VALIDATED"));
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceId()).isNull();
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus())
                .isEqualTo("DEVICE_NOT_SYNCED");
    }

    @Test
    void validatedIdentifierOfUnknownNamespaceLinksViaTheEntraIdentifier() {
        // The CSR subject carries the Entra device id while the server keys devices by the Intune
        // managedDevice id. The agent cannot tell which namespace a validated subject holds, so it
        // sends UNKNOWN and the server resolves across both.
        stubSource();
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(SOURCE_ID, "entra-guid"))
                .thenReturn(List.of(IotDevice.builder().id(11L).organizationId(ORG)
                        .deviceSourceId(SOURCE_ID).sourceDeviceId("intune-guid").build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(identifier("entra-guid", "UNKNOWN", "MICROSOFT_VALIDATED"));
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceId()).isEqualTo(11L);
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus()).isEqualTo("MATCHED");
    }

    @Test
    void unknownNamespaceIdentifierLinksWhenAFormerRegistrationIsOrphaned() {
        // Repository eligibility is deliberately represented here: the old row carries the same
        // identifier but is ORPHANED, so only the current REGISTERED row may reach correlation.
        stubSource();
        IotDevice currentRegistration = IotDevice.builder().id(12L).organizationId(ORG)
                .deviceSourceId(SOURCE_ID).sourceDeviceId("current-managed-device-id").build();
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(
                SOURCE_ID, "0e1d2c3b-0000-4000-8000-00000000d001"))
                .thenReturn(List.of(currentRegistration));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(identifier(
                "0e1d2c3b-0000-4000-8000-00000000d001",
                "UNKNOWN",
                "MICROSOFT_VALIDATED"));
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceId()).isEqualTo(12L);
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus()).isEqualTo("MATCHED");
    }

    @Test
    void unknownNamespaceIdentifierMatchingTwoDevicesIsAmbiguousAndNeverLinks() {
        stubSource();
        when(deviceRepository.findRegisteredBySourceScopedIdentifier(SOURCE_ID, "shared-guid"))
                .thenReturn(List.of(IotDevice.builder().id(11L).build(),
                        IotDevice.builder().id(12L).build()));
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(identifier("shared-guid", "UNKNOWN", "MICROSOFT_VALIDATED"));
        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceId()).isNull();
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus()).isEqualTo("AMBIGUOUS");
    }

    @Test
    void unknownNamespaceIdentifierThatIsOnlyAssertedNeverLinks() {
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(identifier("entra-guid", "UNKNOWN", "ASSERTED"));
        service().handle(message);

        verify(deviceRepository, never()).findRegisteredBySourceScopedIdentifier(any(), any());
        ArgumentCaptor<IotCertificateEnrollment> enrollment =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollment.capture());
        assertThat(enrollment.getAllValues().getFirst().getDeviceMatchStatus())
                .isEqualTo("IDENTIFIER_UNVERIFIED");
    }

    // ---- idempotency ---------------------------------------------------------------------------

    @Test
    void duplicateDeliveryDoesNotCreateAnotherCertificateOrEvent() {
        stubSource();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(101L).organizationId(ORG).deviceSourceId(SOURCE_ID)
                .csrFingerprintSha256("cd".repeat(32)).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                ORG, SOURCE_ID, "tx-1")).thenReturn(Optional.of(enrollment));
        when(certificateRepository.findByEnrollmentId(101L))
                .thenReturn(Optional.of(IotDeviceCertificate.builder().id(202L)
                        .fingerprintSha1("ef".repeat(20))
                        .fingerprintSha256("ab".repeat(32))
                        .issuerDn("CN=ManagementCA")
                        .serialNumber("01AF")
                        .build()));

        service().handle(validMessage());

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void duplicateTransactionWithDifferentCertificateIsRejected() {
        stubSource();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(101L).organizationId(ORG).deviceSourceId(SOURCE_ID)
                .csrFingerprintSha256("cd".repeat(32)).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                ORG, SOURCE_ID, "tx-1")).thenReturn(Optional.of(enrollment));
        when(certificateRepository.findByEnrollmentId(101L))
                .thenReturn(Optional.of(IotDeviceCertificate.builder().id(202L)
                        .fingerprintSha1("ef".repeat(20))
                        .fingerprintSha256("ef".repeat(32))
                        .issuerDn("CN=ManagementCA")
                        .serialNumber("01AF")
                        .build()));

        service().handle(validMessage());

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void conflictingCsrFingerprintForTheSameTransactionIsRejected() {
        stubSource();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(101L).organizationId(ORG).deviceSourceId(SOURCE_ID)
                .csrFingerprintSha256("11".repeat(32)).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                ORG, SOURCE_ID, "tx-1")).thenReturn(Optional.of(enrollment));

        service().handle(validMessage());   // carries csr fingerprint cd..cd

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    // ---- validation gates ------------------------------------------------------------------------

    @Test
    void onlyTheCurrentMessageVersionIsAccepted() {
        // Pre-release: the agent and the server ship together, so there is no compat window.
        ScepCertificateIssuedMessage tooOld = validMessage();
        tooOld.setMessageVersion(2);
        ScepCertificateIssuedMessage tooNew = validMessage();
        tooNew.setMessageVersion(4);

        service().handle(tooOld);
        service().handle(tooNew);

        verify(organizationRepository, never()).existsById(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void invalidCertificateMetadataIsDroppedBeforeEnrollmentWrite() {
        stubSource();
        ScepCertificateIssuedMessage message = validMessage();
        message.setValidTo(message.getValidFrom());

        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void outOfOrderLifecycleIsDroppedBeforeEnrollmentWrite() {
        stubSource();
        ScepCertificateIssuedMessage message = validMessage();
        message.setValidatedAt("2026-08-26T10:59:56Z");

        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    /**
     * Issuance must take the device lock before the enrollment lock, because the sync's orphan
     * batch locks stale devices and then their enrollments. Acquiring in the opposite order lets
     * an issuance and the sync orphaning its device deadlock against each other, so the ordering
     * itself is the thing under test — asserting the calls happen is not enough.
     */
    @Test
    void deviceIsResolvedBeforeTheEnrollmentRowIsLocked() {
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();
        when(deviceRepository.findRegisteredBySourceDeviceId(SOURCE_ID, "device-guid"))
                .thenReturn(Optional.of(IotDevice.builder().id(77L).build()));
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        ScepCertificateIssuedMessage message = validMessage();
        message.setDeviceIdentifier(
                identifier("device-guid", "MANAGED_DEVICE_ID", "MICROSOFT_VALIDATED"));

        service().handle(message);

        InOrder locks = inOrder(deviceRepository, enrollmentRepository);
        locks.verify(deviceRepository).findRegisteredBySourceDeviceId(SOURCE_ID, "device-guid");
        locks.verify(enrollmentRepository)
                .findByOrganizationIdAndDeviceSourceIdAndTransactionId(ORG, SOURCE_ID, "tx-1");
    }

    @Test
    void initialEnrollmentWithPriorCertificateIdentityIsDroppedBeforeEnrollmentWrite() {
        stubSource();
        ScepCertificateIssuedMessage message = validMessage();
        message.setPriorCertificateIssuerDn("CN=ManagementCA");
        message.setPriorCertificateSerialNumber("01AF");

        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    // ---- requested / result shells ---------------------------------------------------------------

    @Test
    void requestedEventCreatesReceivedShellWithoutAProfile() {
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();

        service().handleRequested(requestedMessage());

        ArgumentCaptor<IotCertificateEnrollment> captor =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository).save(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("RECEIVED");
        assertThat(captor.getValue().getDeviceMatchStatus()).isEqualTo("NOT_ASSERTED");
        assertThat(captor.getValue().getProfileId()).isNull();
        assertThat(captor.getValue().getProfileResolutionStatus()).isEqualTo("PENDING_SYNC");
        verify(eventService).recordEnrollment(any(), eq(DeviceEventType.CERTIFICATE_REQUESTED),
                eq("RECEIVED"), any(), any(), any(),
                argThat(key -> key.startsWith("scep-requested:enr_")), any());
    }

    @Test
    void rejectedResultUpdatesExistingEnrollmentAndRecordsEvent() {
        stubSource();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(101L).enrollmentXref("enr_existing").organizationId(ORG)
                .deviceSourceId(SOURCE_ID)
                .transactionId("tx-1").status("RECEIVED").retryable(false).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                ORG, SOURCE_ID, "tx-1")).thenReturn(Optional.of(enrollment));
        when(enrollmentRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service().handleResult(resultMessage("REJECTED", "INTUNE_VALIDATION"));

        assertThat(enrollment.getStatus()).isEqualTo("REJECTED");
        assertThat(enrollment.getFailureStage()).isEqualTo("INTUNE_VALIDATION");
        verify(eventService).recordEnrollment(any(), eq(DeviceEventType.CHALLENGE_REJECTED),
                eq("REJECTED"), any(), any(), any(),
                eq("scep-result:REJECTED:enr_existing"), any());
        verify(iotAudit).enrollmentFailed(eq(ORG), any(), isNull(), eq("enr_existing"),
                eq("INTUNE_VALIDATION"), eq(false), eq("SCEP_ERR"));
    }

    @Test
    void failedResultBeforeRequestCreatesFailedEnrollment() {
        stubSource();
        stubNoExistingEnrollment();
        stubEnrollmentSave();

        service().handleResult(resultMessage("FAILED", "CA_SIGNING"));

        ArgumentCaptor<IotCertificateEnrollment> captor =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, atLeastOnce()).save(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("FAILED");
        assertThat(captor.getValue().getFailureStage()).isEqualTo("CA_SIGNING");
        assertThat(captor.getValue().getProfileId()).isNull();
        verify(eventService).recordEnrollment(any(), eq(DeviceEventType.CERTIFICATE_ENROLLMENT_FAILED),
                eq("FAILED"), any(), any(), any(),
                argThat(key -> key.startsWith("scep-result:FAILED:enr_")), any());
    }

    @Test
    void resultForAnUnknownSourceIsDropped() {
        when(sourceRepository.findByOrganizationIdAndConnectionProfileRef(ORG, SOURCE_REF))
                .thenReturn(Optional.empty());

        service().handleResult(resultMessage("FAILED", "CA_SIGNING"));

        verify(enrollmentRepository, never()).save(any());
        verify(iotAudit).enrollmentFailed(ORG, null, SOURCE_REF, null, "CA_SIGNING", false, "SCEP_ERR");
    }

    // ---- fixtures --------------------------------------------------------------------------------

    private static ScepCertificateIssuedMessage.DeviceIdentifier identifier(
            String value, String type, String assurance) {
        ScepCertificateIssuedMessage.DeviceIdentifier identifier =
                new ScepCertificateIssuedMessage.DeviceIdentifier();
        identifier.setValue(value);
        identifier.setType(type);
        identifier.setAssurance(assurance);
        identifier.setProvider("INTUNE");
        return identifier;
    }

    private static ScepCertRequestedMessage requestedMessage() {
        ScepCertRequestedMessage message = new ScepCertRequestedMessage();
        message.setMessageVersion(2);
        message.setRequestId("tx-1");
        message.setCorrelationId("corr-1");
        message.setOrganizationId("42");
        message.setConnectionProfileRef(SOURCE_REF);
        message.setEndpointId(SOURCE_REF);
        message.setIntuneTransactionId("tx-1");
        message.setPublicKeyAlgorithm("RSA");
        message.setKeySize(2048);
        message.setRequestedAt("2026-08-26T11:59:00Z");
        return message;
    }

    private static ScepCertResultMessage resultMessage(String status, String stage) {
        ScepCertResultMessage message = new ScepCertResultMessage();
        message.setMessageVersion(2);
        message.setRequestId("tx-1");
        message.setCorrelationId("corr-1");
        message.setOrganizationId("42");
        message.setConnectionProfileRef(SOURCE_REF);
        message.setEndpointId(SOURCE_REF);
        message.setIntuneTransactionId("tx-1");
        message.setStatus(status);
        message.setStage(stage);
        message.setRetryable(false);
        message.setErrorCode("SCEP_ERR");
        message.setErrorMessage("boom");
        message.setOccurredAt("2026-08-26T12:00:00Z");
        return message;
    }

    private IotCertificateIngestionService service() {
        return new IotCertificateIngestionService(
                organizationRepository, sourceRepository, profileRepository,
                configurationRepository, enrollmentRepository, certificateRepository,
                deviceRepository,
                new IotCertificateSupersessionService(
                        certificateRepository, enrollmentRepository, eventService, CLOCK),
                eventService,
                new IotCertificateDeviceLinkService(deviceRepository, certificateRepository, eventService),
                alertPublisher, featureFlagService,
                JsonMapper.builderWithJackson2Defaults().build(), CLOCK, iotAudit);
    }

    private static ScepCertificateIssuedMessage validMessage() {
        ScepCertificateIssuedMessage message = new ScepCertificateIssuedMessage();
        message.setMessageVersion(3);
        message.setRequestId("tx-1");
        message.setCorrelationId("corr-1");
        message.setOrganizationId("42");
        message.setConnectionProfileRef(SOURCE_REF);
        message.setEndpointId(SOURCE_REF);
        message.setIntuneTransactionId("tx-1");
        message.setCsrFingerprintSha256("cd".repeat(32));
        message.setEnrollmentType("INITIAL");
        message.setCaProvider("ejbca");
        message.setCaName("ManagementCA");
        message.setEndEntityName("device-one");
        message.setIssuer("CN=ManagementCA");
        message.setSerialNumber("01:af");
        message.setStatus("ISSUED");
        message.setSubjectDn("CN=device-one");
        message.setCommonName("device-one");
        message.setSubjectAltNames(List.of(new ScepCertificateIssuedMessage.SubjectAlternativeName(
                "uniformResourceIdentifier", null, "urn:certping:device:one")));
        message.setFingerprintSha256("ab".repeat(32));
        message.setFingerprintSha1("ef".repeat(20));
        message.setValidFrom("2026-08-26T11:00:00Z");
        message.setValidTo("2027-08-26T11:00:00Z");
        message.setSignatureAlgorithm("SHA256withRSA");
        message.setSignatureAlgorithmOid("1.2.840.113549.1.1.11");
        message.setPublicKeyAlgorithm("RSA");
        message.setKeySize(2048);
        message.setKeyUsage("digitalSignature,keyEncipherment");
        message.setExtendedKeyUsage("1.3.6.1.5.5.7.3.2");
        message.setCertificatePolicyOids(List.of("1.2.3.4"));
        message.setCertificateAuthority(false);
        message.setRequestedAt("2026-08-26T10:59:57Z");
        message.setValidatedAt("2026-08-26T10:59:58Z");
        message.setIssuedAt("2026-08-26T10:59:59Z");
        message.setCompletedAt("2026-08-26T11:00:00Z");
        message.setRespondedAt("2026-08-26T11:00:01Z");
        return message;
    }
}
