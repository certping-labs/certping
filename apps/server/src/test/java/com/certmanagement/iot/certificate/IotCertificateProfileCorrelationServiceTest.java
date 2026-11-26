// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.profile.CertificateCorrelationResult;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateProfileCorrelationServiceTest {
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotCertificateEnrollmentRepository enrollmentRepository;
    @Mock private CertificateProfileRepository profileRepository;
    @Mock private IotDeviceEventService eventService;
    @InjectMocks private IotCertificateProfileCorrelationService service;

    @Test
    void appliesAnExactProviderProfileMatchToCertificateAndEnrollment() {
        IotDeviceSource source = IotDeviceSource.builder().id(10L).organizationId(42L).build();
        IotDeviceCertificate certificate = IotDeviceCertificate.builder()
                .id(20L).certificateXref("cert_1").deviceSourceId(10L).enrollmentId(30L).build();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(30L).organizationId(42L).deviceSourceId(10L)
                .profileResolutionStatus("PENDING_SYNC").build();
        CertificateProfile profile = CertificateProfile.builder()
                .id(40L).profileXref("profile_1").deviceSourceId(10L)
                .providerProfileId("native-1")
                .providerProfileType("#microsoft.graph.macOSScepCertificateProfile").build();
        when(certificateRepository.findAllByDeviceSourceIdAndCertificateXrefIn(
                10L, List.of("cert_1"))).thenReturn(List.of(certificate));
        when(enrollmentRepository.findAllById(List.of(30L))).thenReturn(List.of(enrollment));
        when(profileRepository.findAllByDeviceSourceIdAndProviderProfileIdIn(
                10L, List.of("native-1"))).thenReturn(List.of(profile));
        OffsetDateTime now = OffsetDateTime.parse("2026-08-28T00:00:00Z");

        service.reconcile(source, "sync_1", List.of(new CertificateCorrelationResult(
                "cert_1", "MATCHED", "native-1",
                "#microsoft.graph.macOSScepCertificateProfile", "SHA1")), now);

        assertThat(certificate.getProfileId()).isEqualTo(40L);
        assertThat(enrollment.getProfileId()).isEqualTo(40L);
        assertThat(enrollment.getProfileResolutionStatus()).isEqualTo("MATCHED");
        verify(eventService).recordEnrollment(eq(enrollment),
                eq(DeviceEventType.CERTIFICATE_PROFILE_MATCHED), eq("MATCHED"), any(), any(),
                eq("sync_1"), eq("sync_1:profile-correlation:cert_1"), eq(now));
        verify(enrollmentRepository).saveAll(List.of(enrollment));
        verify(certificateRepository).saveAll(List.of(certificate));
    }

    @Test
    void preservesNoProfileAndRecordsAnAmbiguousOutcome() {
        IotDeviceSource source = IotDeviceSource.builder().id(10L).organizationId(42L).build();
        IotDeviceCertificate certificate = IotDeviceCertificate.builder()
                .id(20L).certificateXref("cert_1").deviceSourceId(10L).enrollmentId(30L).build();
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(30L).organizationId(42L).deviceSourceId(10L)
                .profileResolutionStatus("PENDING_SYNC").build();
        when(certificateRepository.findAllByDeviceSourceIdAndCertificateXrefIn(
                10L, List.of("cert_1"))).thenReturn(List.of(certificate));
        when(enrollmentRepository.findAllById(List.of(30L))).thenReturn(List.of(enrollment));

        service.reconcile(source, "sync_1", List.of(new CertificateCorrelationResult(
                "cert_1", "AMBIGUOUS", null, null, null)), OffsetDateTime.now());

        assertThat(enrollment.getProfileId()).isNull();
        assertThat(enrollment.getProfileResolutionStatus()).isEqualTo("AMBIGUOUS");
        ArgumentCaptor<String> status = ArgumentCaptor.forClass(String.class);
        verify(eventService).recordEnrollment(eq(enrollment),
                eq(DeviceEventType.CERTIFICATE_PROFILE_UNMATCHED), status.capture(), any(), any(),
                eq("sync_1"), eq("sync_1:profile-correlation:cert_1"), any());
        assertThat(status.getValue()).isEqualTo("AMBIGUOUS");
    }
}
