// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateQueryServiceTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-27T12:00:00Z"), ZoneOffset.UTC);
    private static final long ORG_ID = 42L;

    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotCertificateEnrollmentRepository enrollmentRepository;
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private CertificateProfileRepository profileRepository;
    @Mock private IotDeviceEventService deviceEventService;

    private IotCertificateQueryService service;

    @BeforeEach
    void setUp() {
        service = new IotCertificateQueryService(certificateRepository, enrollmentRepository,
                deviceRepository, sourceRepository, profileRepository,
                deviceEventService, JsonMapper.builderWithJackson2Defaults().build(), CLOCK);
        lenient().when(profileRepository.findAllById(any())).thenReturn(List.of());
        lenient().when(deviceRepository.findAllByIdsIncludingArchived(any())).thenReturn(List.of());
    }

    @Test
    void listResolvesDeviceProfileAndSourceXrefsBeforeSearching() {
        when(deviceRepository.findByDeviceXrefIncludingArchived("dev-1", ORG_ID))
                .thenReturn(Optional.of(device(1L, "dev-1", "Gateway", DeviceStatus.REGISTERED)));
        when(profileRepository.findByProfileXrefAndOrganizationId("prof-1", ORG_ID))
                .thenReturn(Optional.of(profile(2L, "prof-1", "IoT profile")));
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", ORG_ID))
                .thenReturn(Optional.of(source(3L)));
        when(certificateRepository.search(eq(ORG_ID), eq(1L), eq(2L), eq(3L), eq("EJBCA"),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, "dev-1", "prof-1", "src-1", "ejbca", null, null, null, null,
                PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), eq(1L), eq(2L), eq(3L), eq("EJBCA"),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listThrowsNotFoundForUnknownDeviceXref() {
        when(deviceRepository.findByDeviceXrefIncludingArchived("missing", ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.list(ORG_ID, "missing", null, null, null, null, null, null, null,
                PageRequest.of(0, 20)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void listThrowsNotFoundForUnknownProfileXref() {
        when(profileRepository.findByProfileXrefAndOrganizationId("missing", ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.list(ORG_ID, null, "missing", null, null, null, null, null, null,
                PageRequest.of(0, 20)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void listThrowsNotFoundForUnknownSourceXref() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("missing", ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.list(ORG_ID, null, null, "missing", null, null, null, null, null,
                PageRequest.of(0, 20)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void listAppliesExpiredStatusAsAnUpperValidToBound() {
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), eq(OffsetDateTime.now(CLOCK)), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null,
                IotCertificateQueryService.StatusFilter.EXPIRED, null, null, null, PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), eq(OffsetDateTime.now(CLOCK)), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listAppliesIssuedStatusAsALowerValidToBound() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now.plusDays(30)), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null,
                IotCertificateQueryService.StatusFilter.ISSUED, null, null, null, PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now.plusDays(30)), isNull(), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listAppliesExpiringStatusAsARange() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now), eq(now.plusDays(30)), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null,
                IotCertificateQueryService.StatusFilter.EXPIRING, null, null, null, PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now), eq(now.plusDays(30)), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listStatusFilterTakesPrecedenceOverExpiringWithinDays() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), eq(now), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null,
                IotCertificateQueryService.StatusFilter.EXPIRED, 7, null, null, PageRequest.of(0, 20));

        // The EXPIRED bound (validToBefore=now) is used, not the expiringWithinDays=7 bound.
        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), eq(now), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listAppliesExpiringWithinDaysWhenNoStatusGiven() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now), eq(now.plusDays(7)), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null, null, 7, null, null, PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                eq(now), eq(now.plusDays(7)), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listRejectsNonPositiveExpiringWithinDays() {
        assertThatThrownBy(() -> service.list(ORG_ID, null, null, null, null, null, 0, null, null,
                PageRequest.of(0, 20)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void listFiltersByRenewalStateNormalisedToUpperCase() {
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), eq("EXPIRED"), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.list(ORG_ID, null, null, null, null, null, null, "expired", null,
                PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), eq("EXPIRED"), isNull(), any(Pageable.class));
    }

    @Test
    void listDerivesDisplayStatusAndMapsDeviceAndProfileSummaries() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        IotDeviceCertificate expired = certificateRow("cert-expired", 1L, 10L, now.minusDays(1));
        IotDeviceCertificate expiring = certificateRow("cert-expiring", 1L, 10L, now.plusDays(5));
        IotDeviceCertificate healthy = certificateRow("cert-healthy", null, 10L, now.plusDays(90));
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(expired, expiring, healthy)));
        when(deviceRepository.findAllByIdsIncludingArchived(List.of(1L)))
                .thenReturn(List.of(device(1L, "dev-1", "Gateway", DeviceStatus.REGISTERED)));
        when(profileRepository.findAllById(List.of(10L)))
                .thenReturn(List.of(profile(10L, "prof-1", "IoT profile")));

        Page<CertificateListItem> page = service.list(ORG_ID, null, null, null, null, null, null, null, null,
                PageRequest.of(0, 20));

        assertThat(page.getContent()).extracting(CertificateListItem::status)
                .containsExactly("EXPIRED", "EXPIRING", "ISSUED");
        assertThat(page.getContent().get(0).device().deviceXref()).isEqualTo("dev-1");
        assertThat(page.getContent().get(2).device()).isNull();
        assertThat(page.getContent().get(0).profile().profileXref()).isEqualTo("prof-1");
        assertThat(page.getContent().get(0).caName()).isEqualTo("ManagementCA");
        assertThat(page.getContent().get(0).certificateScope()).isEqualTo("DEVICE");
        assertThat(page.getContent().get(0).signatureAlgorithmOid()).isEqualTo("1.2.840.113549.1.1.11");
        assertThat(page.getContent().get(0).issuedAt()).isNotNull();
        assertThat(page.getContent().get(1).renewalState()).isEqualTo("NONE");
    }

    /**
     * An unmatched certificate has a null device id, and the batch lookup skips the query entirely
     * when no row on the page has a device. The empty map it substitutes must tolerate the null
     * key: Map.of() rejects one outright instead of missing it, which failed the whole request for
     * the exact population — unmatched certificates — this view exists to surface.
     */
    @Test
    void listServesAPageOnWhichNoCertificateHasADevice() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(
                        certificateRow("cert-a", null, 10L, now.plusDays(90)),
                        certificateRow("cert-b", null, 10L, now.plusDays(60)))));
        when(profileRepository.findAllById(List.of(10L)))
                .thenReturn(List.of(profile(10L, "prof-1", "IoT profile")));

        Page<CertificateListItem> page = service.list(ORG_ID, null, null, null, null, null, null, null, null,
                PageRequest.of(0, 20));

        assertThat(page.getContent()).extracting(CertificateListItem::device).containsOnlyNulls();
        assertThat(page.getContent()).extracting(CertificateListItem::certificateXref)
                .containsExactly("cert-a", "cert-b");
    }

    /**
     * Archiving is a soft delete, so the device is still the certificate's owner. Reporting the
     * summary is only half the fix — without the flag the row is indistinguishable from a live
     * device, and the operator loses the reason the device left the inventory.
     */
    @Test
    void listMarksACertificateHeldByAnArchivedDevice() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        when(certificateRepository.search(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(
                        certificateRow("cert-archived", 1L, 10L, now.plusDays(90)),
                        certificateRow("cert-live", 2L, 10L, now.plusDays(90)))));
        when(deviceRepository.findAllByIdsIncludingArchived(List.of(1L, 2L)))
                .thenReturn(List.of(archived(device(1L, "dev-1", "Gateway", DeviceStatus.ORPHANED)),
                        device(2L, "dev-2", "Sensor", DeviceStatus.REGISTERED)));
        when(profileRepository.findAllById(List.of(10L)))
                .thenReturn(List.of(profile(10L, "prof-1", "IoT profile")));

        Page<CertificateListItem> page = service.list(ORG_ID, null, null, null, null, null, null, null, null,
                PageRequest.of(0, 20));

        assertThat(page.getContent().get(0).device().deviceXref()).isEqualTo("dev-1");
        assertThat(page.getContent().get(0).device().archived()).isTrue();
        assertThat(page.getContent().get(1).device().archived()).isFalse();
    }

    @Test
    void getMarksADetailWhoseDeviceWasArchived() {
        IotDeviceCertificate certificate = certificateRow("cert-1", 1L, 10L, OffsetDateTime.now(CLOCK).plusDays(90));
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "cert-1"))
                .thenReturn(Optional.of(certificate));
        when(enrollmentRepository.findById(99L)).thenReturn(Optional.of(enrollment(99L)));
        when(deviceRepository.findByIdIncludingArchived(1L))
                .thenReturn(Optional.of(archived(device(1L, "dev-1", "Gateway", DeviceStatus.ORPHANED))));
        when(profileRepository.findById(10L)).thenReturn(Optional.of(profile(10L, "prof-1", "IoT profile")));

        CertificateDetail detail = service.get(ORG_ID, "cert-1");

        assertThat(detail.device().deviceXref()).isEqualTo("dev-1");
        assertThat(detail.device().archived()).isTrue();
    }

    @Test
    void certificatesForDeviceScopesByResolvedDeviceId() {
        when(deviceRepository.findByDeviceXrefIncludingArchived("dev-1", ORG_ID))
                .thenReturn(Optional.of(device(1L, "dev-1", "Gateway", DeviceStatus.REGISTERED)));
        when(certificateRepository.search(eq(ORG_ID), eq(1L), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.certificatesForDevice(ORG_ID, "dev-1", PageRequest.of(0, 20));

        verify(certificateRepository).search(eq(ORG_ID), eq(1L), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void certificatesForDeviceThrowsNotFoundForUnknownDevice() {
        when(deviceRepository.findByDeviceXrefIncludingArchived("missing", ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.certificatesForDevice(ORG_ID, "missing", PageRequest.of(0, 20)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void getReturnsFullDetailWithEnrollmentDeviceAndProfile() {
        IotDeviceCertificate certificate = certificateRow("cert-1", 1L, 10L, OffsetDateTime.now(CLOCK).plusDays(90));
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "cert-1"))
                .thenReturn(Optional.of(certificate));
        when(enrollmentRepository.findById(99L)).thenReturn(Optional.of(enrollment(99L)));
        when(deviceRepository.findByIdIncludingArchived(1L)).thenReturn(Optional.of(device(1L, "dev-1", "Gateway", DeviceStatus.REGISTERED)));
        when(profileRepository.findById(10L)).thenReturn(Optional.of(profile(10L, "prof-1", "IoT profile")));

        CertificateDetail detail = service.get(ORG_ID, "cert-1");

        assertThat(detail.certificateXref()).isEqualTo("cert-1");
        assertThat(detail.enrollment().enrollmentXref()).isEqualTo("enr-99");
        assertThat(detail.device().deviceXref()).isEqualTo("dev-1");
        assertThat(detail.device().status()).isEqualTo("REGISTERED");
        assertThat(detail.profile().profileXref()).isEqualTo("prof-1");
        assertThat(detail.caName()).isEqualTo("ManagementCA");
        assertThat(detail.certificateScope()).isEqualTo("DEVICE");
        assertThat(detail.signatureAlgorithmOid()).isEqualTo("1.2.840.113549.1.1.11");
        assertThat(detail.issuedAt()).isNotNull();
        assertThat(detail.renewalState()).isEqualTo("NONE");
    }

    @Test
    void getOmitsDeviceWhenNoDeviceIsLinked() {
        IotDeviceCertificate certificate = certificateRow("cert-1", null, 10L, OffsetDateTime.now(CLOCK).plusDays(90));
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "cert-1"))
                .thenReturn(Optional.of(certificate));
        when(enrollmentRepository.findById(99L)).thenReturn(Optional.of(enrollment(99L)));
        when(profileRepository.findById(10L)).thenReturn(Optional.of(profile(10L, "prof-1", "IoT profile")));

        CertificateDetail detail = service.get(ORG_ID, "cert-1");

        assertThat(detail.device()).isNull();
    }

    @Test
    void getThrowsResourceNotFoundForUnknownCertificate() {
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "missing"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.get(ORG_ID, "missing"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void historyDelegatesToDeviceEventServiceWithTheResolvedEnrollmentId() {
        IotDeviceCertificate certificate = certificateRow("cert-1", 1L, 10L, OffsetDateTime.now(CLOCK).plusDays(90));
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "cert-1"))
                .thenReturn(Optional.of(certificate));
        Pageable pageable = PageRequest.of(0, 20);
        Page<DeviceEventDto> expected = new PageImpl<>(List.of());
        when(deviceEventService.listForEnrollment(99L, ORG_ID, pageable)).thenReturn(expected);

        Page<DeviceEventDto> history = service.history(ORG_ID, "cert-1", pageable);

        assertThat(history).isSameAs(expected);
    }

    @Test
    void historyThrowsResourceNotFoundForUnknownCertificate() {
        when(certificateRepository.findByOrganizationIdAndCertificateXref(ORG_ID, "missing"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.history(ORG_ID, "missing", PageRequest.of(0, 20)))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    private static IotDeviceCertificate certificateRow(
            String xref, Long deviceId, long profileId, OffsetDateTime validTo) {
        return IotDeviceCertificate.builder()
                .certificateXref(xref)
                .enrollmentId(99L)
                .organizationId(ORG_ID)
                .deviceSourceId(3L)
                .profileId(profileId)
                .deviceId(deviceId)
                .caProvider("EJBCA")
                .caName("ManagementCA")
                .issuerDn("CN=Test CA")
                .certificateScope("DEVICE")
                .serialNumber("1A")
                .subjectDn("CN=device")
                .commonName("device")
                .subjectAltNamesJson("[]")
                .fingerprintSha256("a".repeat(64))
                .validFrom(validTo.minusDays(180))
                .validTo(validTo)
                .publicKeyAlgorithm("RSA")
                .keySize(2048)
                .signatureAlgorithm("SHA256withRSA")
                .signatureAlgorithmOid("1.2.840.113549.1.1.11")
                .keyUsageJson("[]")
                .extendedKeyUsageOidsJson("[]")
                .certificatePolicyOidsJson("[]")
                .certificateAuthority(false)
                .status("ISSUED")
                .renewalState("NONE")
                .nudgeAttempts(0)
                .issuedAt(validTo.minusDays(180))
                .createdAt(validTo.minusDays(180))
                .updatedAt(validTo.minusDays(180))
                .build();
    }

    private static IotCertificateEnrollment enrollment(long id) {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        return IotCertificateEnrollment.builder()
                .id(id)
                .enrollmentXref("enr-" + id)
                .organizationId(ORG_ID)
                .deviceSourceId(3L)
                .profileId(10L)
                .endpointId("default")
                .transactionId("txn-1")
                .enrollmentType("INITIAL")
                .deviceMatchStatus("MATCHED")
                .status("ISSUED")
                .retryable(false)
                .requestedAt(now)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private static IotDevice device(long id, String deviceXref, String deviceName, DeviceStatus status) {
        return IotDevice.builder()
                .id(id)
                .deviceXref(deviceXref)
                .organizationId(ORG_ID)
                .deviceSourceId(3L)
                .sourceDeviceId("src-device-" + id)
                .deviceName(deviceName)
                .status(status)
                .build();
    }

    private static IotDevice archived(IotDevice device) {
        device.setIsDeleted(true);
        return device;
    }

    private static CertificateProfile profile(long id, String profileXref, String name) {
        return CertificateProfile.builder()
                .id(id)
                .profileXref(profileXref)
                .organizationId(ORG_ID)
                .deviceSourceId(3L)
                .name(name)
                .targetPlatform("WINDOWS")
                .targetVariant("DEFAULT")
                .providerProfileType("SCEP")
                .build();
    }

    private static IotDeviceSource source(long id) {
        return IotDeviceSource.builder()
                .id(id)
                .sourceXref("src-1")
                .organizationId(ORG_ID)
                .build();
    }
}
