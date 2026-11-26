// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.profile.CertificateProfile;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateRenewalIngestionServiceTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-26T12:00:00Z"), ZoneOffset.UTC);
    private static final CertificateProfile PROFILE = CertificateProfile.builder()
            .id(7L).profileXref("profile-1").organizationId(42L).deviceSourceId(9L).build();
    private static final IotDeviceSource SOURCE = IotDeviceSource.builder()
            .id(9L).organizationId(42L).sourceXref("src_1")
            .connectionProfileRef("intune-primary").build();

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

    @BeforeEach
    void enableFeature() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null))
                .thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L))
                .thenReturn(true);
        lenient().when(organizationRepository.existsById(42L)).thenReturn(true);
        lenient().when(sourceRepository.findByOrganizationIdAndConnectionProfileRef(
                        42L, "intune-primary"))
                .thenReturn(Optional.of(SOURCE));
        lenient().when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(PROFILE));
    }

    @Test
    void renewalInheritsDeviceFromExactPriorCertificateAndRecordsProvenance() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        IotDeviceCertificate priorCertificate = IotDeviceCertificate.builder()
                .id(55L).certificateXref("crt_prior").organizationId(42L).deviceSourceId(9L)
                .deviceId(11L).caProvider("EJBCA").issuerDn("CN=ManagementCA")
                .serialNumber("01AF").build();
        stubNewEnrollment();
        when(certificateRepository.findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                42L, "EJBCA", "CN=ManagementCA", "01AF"))
                .thenReturn(Optional.of(priorCertificate));

        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollments =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollments.capture());
        assertThat(enrollments.getAllValues().getFirst()).satisfies(enrollment -> {
            assertThat(enrollment.getEnrollmentType()).isEqualTo("RENEWAL");
            assertThat(enrollment.getPriorCertificateIssuerDn()).isEqualTo("CN=ManagementCA");
            assertThat(enrollment.getPriorCertificateSerialNumber()).isEqualTo("01AF");
            assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("INHERITED_FROM_RENEWAL");
            assertThat(enrollment.getDeviceId()).isEqualTo(11L);
            assertThat(enrollment.getAssertedSourceDeviceId()).isNull();
        });
        ArgumentCaptor<IotDeviceCertificate> issued =
                ArgumentCaptor.forClass(IotDeviceCertificate.class);
        verify(certificateRepository).save(issued.capture());
        assertThat(issued.getValue()).satisfies(certificate -> {
            assertThat(certificate.getDeviceId()).isEqualTo(11L);
            assertThat(certificate.getPublicKeyCurve()).isEqualTo("1.2.840.10045.3.1.7");
            assertThat(certificate.getSubjectAltNamesJson())
                    .contains("1.3.6.1.4.1.311.20.2.3")
                    .contains("user@corp.example");
        });
        verify(deviceRepository, never())
                .findRegisteredBySourceDeviceId(any(), any());

        ArgumentCaptor<String> statuses = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(eventService, times(6)).recordEnrollment(any(), any(), statuses.capture(), any(),
                details.capture(), any(), any(), any());
        int provenanceEvent = statuses.getAllValues().indexOf("INHERITED_FROM_RENEWAL");
        assertThat(details.getAllValues().get(provenanceEvent))
                .containsEntry("sourceCertificateXref", "crt_prior")
                .containsEntry("priorCertificateSerialNumber", "01AF");
    }

    @Test
    void renewalWithUnknownPriorCertificateStaysUnlinkedAndAuditable() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        stubNewEnrollment();
        when(certificateRepository.findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                42L, "EJBCA", "CN=ManagementCA", "01AF")).thenReturn(Optional.empty());

        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollments =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollments.capture());
        assertThat(enrollments.getAllValues().getFirst()).satisfies(enrollment -> {
            assertThat(enrollment.getDeviceId()).isNull();
            assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("RENEWAL_SOURCE_NOT_FOUND");
        });
        ArgumentCaptor<DeviceEventType> eventTypes = ArgumentCaptor.forClass(DeviceEventType.class);
        ArgumentCaptor<String> statuses = ArgumentCaptor.forClass(String.class);
        verify(eventService, times(6)).recordEnrollment(any(), eventTypes.capture(), statuses.capture(),
                any(), any(), any(), any(), any());
        int provenanceEvent = statuses.getAllValues().indexOf("RENEWAL_SOURCE_NOT_FOUND");
        assertThat(eventTypes.getAllValues().get(provenanceEvent))
                .isEqualTo(DeviceEventType.CERTIFICATE_DEVICE_UNMATCHED);
    }

    @Test
    void renewalSourceWithoutDeviceLinkUsesUnmatchedEventType() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        stubNewEnrollment();
        when(certificateRepository.findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                42L, "EJBCA", "CN=ManagementCA", "01AF"))
                .thenReturn(Optional.of(IotDeviceCertificate.builder()
                        .certificateXref("crt_unlinked").deviceSourceId(9L).deviceId(null).build()));

        service().handle(message);

        ArgumentCaptor<IotCertificateEnrollment> enrollments =
                ArgumentCaptor.forClass(IotCertificateEnrollment.class);
        verify(enrollmentRepository, times(2)).save(enrollments.capture());
        assertThat(enrollments.getAllValues().getFirst()).satisfies(enrollment -> {
            assertThat(enrollment.getDeviceId()).isNull();
            assertThat(enrollment.getDeviceMatchStatus()).isEqualTo("INHERITED_FROM_RENEWAL");
        });
        ArgumentCaptor<DeviceEventType> eventTypes = ArgumentCaptor.forClass(DeviceEventType.class);
        ArgumentCaptor<String> statuses = ArgumentCaptor.forClass(String.class);
        verify(eventService, times(6)).recordEnrollment(any(), eventTypes.capture(), statuses.capture(),
                any(), any(), any(), any(), any());
        int provenanceEvent = statuses.getAllValues().indexOf("INHERITED_FROM_RENEWAL");
        assertThat(eventTypes.getAllValues().get(provenanceEvent))
                .isEqualTo(DeviceEventType.CERTIFICATE_DEVICE_UNMATCHED);
    }

    @Test
    void renewalDoesNotInheritAcrossDeviceSources() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        stubNewEnrollment();
        when(certificateRepository.findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                42L, "EJBCA", "CN=ManagementCA", "01AF"))
                .thenReturn(Optional.of(IotDeviceCertificate.builder()
                        .certificateXref("crt_other_source").deviceSourceId(99L).deviceId(11L).build()));

        service().handle(message);

        ArgumentCaptor<IotDeviceCertificate> issued =
                ArgumentCaptor.forClass(IotDeviceCertificate.class);
        verify(certificateRepository).save(issued.capture());
        assertThat(issued.getValue().getDeviceId()).isNull();
    }

    @Test
    void shellWithoutFingerprintAcceptsTheIssuedCertificateAndBackfillsIt() {
        // Invariant 7: a detail the shell did not carry is unknown, not conflicting — the issued
        // certificate must never be dropped because of it.
        IotCertificateEnrollment existing = IotCertificateEnrollment.builder()
                .id(101L).enrollmentXref("enr_shell").organizationId(42L).deviceSourceId(9L)
                .profileResolutionStatus("PENDING_SYNC")
                .csrFingerprintSha256(null).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(42L, 9L, "tx-1"))
                .thenReturn(Optional.of(existing));
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(certificateRepository.findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                42L, "EJBCA", "CN=ManagementCA", "01AF")).thenReturn(Optional.empty());
        when(enrollmentRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service().handle(validRenewalMessage());

        assertThat(existing.getCsrFingerprintSha256()).isEqualTo("cd".repeat(32));
        verify(certificateRepository).save(any());
    }

    @Test
    void absentReplayFingerprintStillIdentifiesTheStoredTransaction() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        message.setCsrFingerprintSha256(null);
        IotCertificateEnrollment existing = IotCertificateEnrollment.builder()
                .id(101L).enrollmentXref("enr_shell").organizationId(42L).deviceSourceId(9L)
                .profileResolutionStatus("PENDING_SYNC")
                .csrFingerprintSha256("cd".repeat(32)).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(42L, 9L, "tx-1"))
                .thenReturn(Optional.of(existing));
        when(certificateRepository.findByEnrollmentId(101L))
                .thenReturn(Optional.of(IotDeviceCertificate.builder()
                        .fingerprintSha1("ef".repeat(20))
                        .fingerprintSha256("ab".repeat(32)).issuerDn("CN=ManagementCA")
                        .serialNumber("02AF").build()));

        service().handle(message);

        // The stored fingerprint is kept; the redelivered certificate is verified, not re-created.
        assertThat(existing.getCsrFingerprintSha256()).isEqualTo("cd".repeat(32));
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void bothNullFingerprintsStillIdentifyTheSameTransaction() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        message.setCsrFingerprintSha256(null);
        IotCertificateEnrollment existing = IotCertificateEnrollment.builder()
                .id(101L).organizationId(42L).profileId(7L).deviceSourceId(9L)
                .csrFingerprintSha256(null).build();
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(42L, 9L, "tx-1"))
                .thenReturn(Optional.of(existing));
        when(certificateRepository.findByEnrollmentId(101L))
                .thenReturn(Optional.of(IotDeviceCertificate.builder()
                        .fingerprintSha1("ef".repeat(20))
                        .fingerprintSha256("ab".repeat(32)).issuerDn("CN=ManagementCA")
                        .serialNumber("02AF").build()));

        service().handle(message);

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void renewalWithoutPriorCertificateIdentityIsDroppedBeforeEnrollmentWrite() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        message.setPriorCertificateIssuerDn(null);
        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void renewalWithAssertedDeviceIdentityIsDroppedBeforeEnrollmentWrite() {
        ScepCertificateIssuedMessage message = validRenewalMessage();
        ScepCertificateIssuedMessage.DeviceIdentifier unexpected =
                new ScepCertificateIssuedMessage.DeviceIdentifier();
        unexpected.setValue("unexpected-device");
        unexpected.setType("MANAGED_DEVICE_ID");
        unexpected.setAssurance("ASSERTED");
        message.setDeviceIdentifier(unexpected);
        service().handle(message);

        verify(enrollmentRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
    }

    private void stubNewEnrollment() {
        when(enrollmentRepository.findByOrganizationIdAndDeviceSourceIdAndTransactionId(42L, 9L, "tx-1"))
                .thenReturn(Optional.empty());
        when(enrollmentRepository.save(any())).thenAnswer(invocation -> {
            IotCertificateEnrollment enrollment = invocation.getArgument(0);
            if (enrollment.getId() == null) {
                enrollment.setId(101L);
            }
            return enrollment;
        });
        when(certificateRepository.findByEnrollmentId(101L)).thenReturn(Optional.empty());
        when(configurationRepository.findById(7L)).thenReturn(Optional.empty());
        when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    private IotCertificateIngestionService service() {
        IotCertificateDeviceLinkService deviceLinkService = new IotCertificateDeviceLinkService(
                deviceRepository, certificateRepository, eventService);
        return new IotCertificateIngestionService(
                organizationRepository, sourceRepository, profileRepository,
                configurationRepository, enrollmentRepository, certificateRepository,
                deviceRepository,
                new IotCertificateSupersessionService(
                        certificateRepository, enrollmentRepository, eventService, CLOCK),
                eventService,
                deviceLinkService, alertPublisher, featureFlagService, JsonMapper.builderWithJackson2Defaults().build(), CLOCK,
                mock(IotAuditRecorder.class));
    }

    private static ScepCertificateIssuedMessage validRenewalMessage() {
        ScepCertificateIssuedMessage message = new ScepCertificateIssuedMessage();
        message.setMessageVersion(3);
        message.setRequestId("tx-1");
        message.setCorrelationId("corr-1");
        message.setOrganizationId("42");
        message.setConnectionProfileRef("intune-primary");
        message.setEndpointId("intune-primary");
        message.setProfileXref("profile-1");
        message.setIntuneTransactionId("tx-1");
        message.setCsrFingerprintSha256("cd".repeat(32));
        message.setEnrollmentType("RENEWAL");
        message.setPriorCertificateIssuerDn("CN=ManagementCA");
        message.setPriorCertificateSerialNumber("01:af");
        message.setCaProvider("ejbca");
        message.setCaName("ManagementCA");
        message.setIssuer("CN=ManagementCA");
        message.setSerialNumber("02:af");
        message.setStatus("ISSUED");
        message.setSubjectDn("CN=device-one");
        message.setCommonName("device-one");
        message.setSubjectAltNames(List.of(new ScepCertificateIssuedMessage.SubjectAlternativeName(
                "otherName", "1.3.6.1.4.1.311.20.2.3", "user@corp.example")));
        message.setFingerprintSha256("ab".repeat(32));
        message.setFingerprintSha1("ef".repeat(20));
        message.setValidFrom("2026-08-26T11:00:00Z");
        message.setValidTo("2027-08-26T11:00:00Z");
        message.setSignatureAlgorithm("SHA256withECDSA");
        message.setSignatureAlgorithmOid("1.2.840.10045.4.3.2");
        message.setPublicKeyAlgorithm("EC");
        message.setKeySize(256);
        message.setPublicKeyCurve("1.2.840.10045.3.1.7");
        message.setKeyUsage("digitalSignature");
        message.setExtendedKeyUsage("1.3.6.1.5.5.7.3.2");
        message.setCertificatePolicyOids(List.of());
        message.setCertificateAuthority(false);
        message.setRequestedAt("2026-08-26T10:59:57Z");
        message.setValidatedAt("2026-08-26T10:59:58Z");
        message.setIssuedAt("2026-08-26T10:59:59Z");
        message.setCompletedAt("2026-08-26T11:00:00Z");
        message.setRespondedAt("2026-08-26T11:00:01Z");
        return message;
    }
}
