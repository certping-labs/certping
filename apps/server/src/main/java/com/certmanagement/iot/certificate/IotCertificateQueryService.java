// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/** Read side of the certificate inventory: search, detail, device-scoped listing, and history. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateQueryService {

    /** Display-status and default expiring-window threshold, matching the KPI-tile contract. */
    private static final int DEFAULT_EXPIRING_WITHIN_DAYS = 30;

    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceRepository deviceRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final CertificateProfileRepository profileRepository;
    private final IotDeviceEventService deviceEventService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public enum StatusFilter { ISSUED, EXPIRING, EXPIRED }

    @Transactional(readOnly = true)
    public Page<CertificateListItem> list(Long organizationId, String deviceXref, String profileXref,
            String sourceXref, String caProvider, StatusFilter status, Integer expiringWithinDays,
            String renewalState, String search, Pageable pageable) {
        Long deviceId = deviceXref == null ? null : requireDeviceId(organizationId, deviceXref);
        Long profileId = profileXref == null ? null : requireProfileId(organizationId, profileXref);
        Long deviceSourceId = sourceXref == null ? null : requireSourceId(organizationId, sourceXref);
        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime[] validToBounds = validToBounds(now, status, expiringWithinDays);
        Page<IotDeviceCertificate> page = certificateRepository.search(
                organizationId, deviceId, profileId, deviceSourceId, normalizeCaProvider(caProvider),
                validToBounds[0], validToBounds[1], normalizeRenewalState(renewalState),
                normalize(search), pageable);
        return toListItemPage(page, now);
    }

    @Transactional(readOnly = true)
    public Page<CertificateListItem> certificatesForDevice(
            Long organizationId, String deviceXref, Pageable pageable) {
        Long deviceId = requireDeviceId(organizationId, deviceXref);
        Page<IotDeviceCertificate> page = certificateRepository.search(
                organizationId, deviceId, null, null, null, null, null, null, null, pageable);
        return toListItemPage(page, OffsetDateTime.now(clock));
    }

    @Transactional(readOnly = true)
    public CertificateDetail get(Long organizationId, String certificateXref) {
        IotDeviceCertificate certificate = requireCertificate(organizationId, certificateXref);
        IotCertificateEnrollment enrollment = enrollmentRepository.findById(certificate.getEnrollmentId())
                .orElseThrow(() -> {
                    log.error("Data integrity: certificate {} (id={}) references enrollment id={} "
                                    + "which does not exist",
                            certificateXref, certificate.getId(), certificate.getEnrollmentId());
                    return new IllegalStateException(
                            "Certificate " + certificateXref + " references a missing enrollment");
                });
        CertificateDeviceSummary device = certificate.getDeviceId() == null ? null
                : deviceRepository.findByIdIncludingArchived(certificate.getDeviceId())
                        .map(IotCertificateQueryService::toDeviceSummary)
                        .orElse(null);
        // profileId is null while the enrollment's profile resolution is pending — a first-class
        // state under source-first persistence, not an error.
        CertificateProfileSummary profile = certificate.getProfileId() == null ? null
                : profileRepository.findById(certificate.getProfileId())
                        .map(IotCertificateQueryService::toProfileSummary)
                        .orElse(null);
        return toDetail(certificate, enrollment, device, profile, OffsetDateTime.now(clock));
    }

    @Transactional(readOnly = true)
    public Page<DeviceEventDto> history(Long organizationId, String certificateXref, Pageable pageable) {
        IotDeviceCertificate certificate = requireCertificate(organizationId, certificateXref);
        return deviceEventService.listForEnrollment(certificate.getEnrollmentId(), organizationId, pageable);
    }

    private IotDeviceCertificate requireCertificate(Long organizationId, String certificateXref) {
        return certificateRepository.findByOrganizationIdAndCertificateXref(organizationId, certificateXref)
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found: " + certificateXref));
    }

    /** Archived rows included: the certificates of a device an operator hid are still its own. */
    private Long requireDeviceId(Long organizationId, String deviceXref) {
        return deviceRepository.findByDeviceXrefIncludingArchived(deviceXref, organizationId)
                .map(IotDevice::getId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));
    }

    private Long requireProfileId(Long organizationId, String profileXref) {
        return profileRepository.findByProfileXrefAndOrganizationId(profileXref, organizationId)
                .map(CertificateProfile::getId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Certificate profile not found"));
    }

    private Long requireSourceId(Long organizationId, String sourceXref) {
        return sourceRepository.findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .map(IotDeviceSource::getId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device source not found"));
    }

    /**
     * Resolves the {@code status}/{@code expiringWithinDays} filters into {@code valid_to} bounds.
     * {@code status} wins when both are given — combining them adds ambiguity (which bound should
     * yield) without a real use case asking for it.
     */
    private OffsetDateTime[] validToBounds(OffsetDateTime now, StatusFilter status, Integer expiringWithinDays) {
        if (status != null) {
            return switch (status) {
                case ISSUED -> new OffsetDateTime[]{now.plusDays(DEFAULT_EXPIRING_WITHIN_DAYS), null};
                case EXPIRING -> new OffsetDateTime[]{now, now.plusDays(DEFAULT_EXPIRING_WITHIN_DAYS)};
                case EXPIRED -> new OffsetDateTime[]{null, now};
            };
        }
        if (expiringWithinDays != null) {
            if (expiringWithinDays <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiringWithinDays must be positive");
            }
            return new OffsetDateTime[]{now, now.plusDays(expiringWithinDays)};
        }
        return new OffsetDateTime[]{null, null};
    }

    private Page<CertificateListItem> toListItemPage(Page<IotDeviceCertificate> page, OffsetDateTime now) {
        List<IotDeviceCertificate> rows = page.getContent();
        // Archived rows included: a certificate keeps its device when the device is archived, and
        // rendering an empty summary would report it as unattributed instead.
        List<Long> deviceIds = rows.stream().map(IotDeviceCertificate::getDeviceId)
                .filter(Objects::nonNull).distinct().toList();
        // A native IN () with no values is a syntax error, unlike the entity query this replaced.
        Map<Long, IotDevice> devicesById = deviceIds.isEmpty()
                ? Map.of()
                : deviceRepository.findAllByIdsIncludingArchived(deviceIds)
                        .stream().collect(Collectors.toMap(IotDevice::getId, device -> device));
        List<Long> profileIds = rows.stream().map(IotDeviceCertificate::getProfileId)
                .filter(Objects::nonNull).distinct().toList();
        Map<Long, CertificateProfile> profilesById = profileRepository.findAllById(profileIds)
                .stream().collect(Collectors.toMap(CertificateProfile::getId, profile -> profile));
        // deviceId is null for an unmatched certificate, and Map.of() rejects a null key outright
        // rather than missing it, so an all-unmatched page would fail the request.
        return page.map(row -> toListItem(
                row,
                row.getDeviceId() == null ? null : devicesById.get(row.getDeviceId()),
                profilesById.get(row.getProfileId()),
                now));
    }

    private CertificateListItem toListItem(
            IotDeviceCertificate row, IotDevice device, CertificateProfile profile,
            OffsetDateTime now) {
        return new CertificateListItem(
                row.getCertificateXref(), row.getCommonName(), row.getSerialNumber(),
                displayStatus(row, now), row.getValidFrom(), row.getValidTo(), row.getIssuedAt(),
                ChronoUnit.DAYS.between(now, row.getValidTo()),
                row.getCaProvider(), row.getCaName(), row.getIssuerDn(), row.getCertificateScope(),
                device == null ? null : new CertificateDeviceSummary(device.getDeviceXref(),
                        device.getDeviceName(), null, Boolean.TRUE.equals(device.getIsDeleted())),
                profile == null ? null : toProfileSummary(profile),
                row.getPublicKeyAlgorithm(), row.getKeySize(), row.getSignatureAlgorithm(),
                row.getSignatureAlgorithmOid(),
                row.getRenewalState(), row.getNudgeAttempts(), row.getLastNudgedAt(),
                row.getLastNudgeOutcome());
    }

    private CertificateDetail toDetail(IotDeviceCertificate row, IotCertificateEnrollment enrollment,
            CertificateDeviceSummary device, CertificateProfileSummary profile,
            OffsetDateTime now) {
        return new CertificateDetail(
                row.getCertificateXref(), row.getCommonName(), row.getSerialNumber(),
                displayStatus(row, now), row.getValidFrom(), row.getValidTo(), row.getIssuedAt(),
                ChronoUnit.DAYS.between(now, row.getValidTo()),
                row.getCaProvider(), row.getCaName(), row.getIssuerDn(), row.getCertificateScope(),
                row.getSubjectDn(),
                readSans(row.getSubjectAltNamesJson()),
                readStringList(row.getKeyUsageJson()),
                readStringList(row.getExtendedKeyUsageOidsJson()),
                readStringList(row.getCertificatePolicyOidsJson()),
                row.getPublicKeyAlgorithm(), row.getKeySize(), row.getPublicKeyCurve(), row.getSignatureAlgorithm(),
                row.getSignatureAlgorithmOid(),
                row.getSubjectKeyIdentifier(), row.getAuthorityKeyIdentifier(), row.getFingerprintSha256(),
                Boolean.TRUE.equals(row.getCertificateAuthority()),
                row.getCaEndEntityName(), row.getCaProvisionerName(),
                toEnrollmentSummary(enrollment), device, profile,
                row.getRenewalState(), row.getNudgeAttempts(), row.getLastNudgedAt(),
                row.getLastNudgeOutcome());
    }

    private static String normalizeRenewalState(String value) {
        String normalized = normalize(value);
        return normalized == null ? null : normalized.toUpperCase(Locale.ROOT);
    }

    private static CertificateDetail.EnrollmentSummary toEnrollmentSummary(IotCertificateEnrollment enrollment) {
        return new CertificateDetail.EnrollmentSummary(
                enrollment.getEnrollmentXref(), enrollment.getEnrollmentType(), enrollment.getTransactionId(),
                enrollment.getStatus(), enrollment.getDeviceMatchStatus(),
                enrollment.getProfileResolutionStatus(), enrollment.getPriorCertificateSerialNumber(),
                enrollment.getRequestedAt(), enrollment.getValidatedAt(),
                enrollment.getIssuedAt(), enrollment.getCompletedAt());
    }

    private static CertificateDeviceSummary toDeviceSummary(IotDevice device) {
        return new CertificateDeviceSummary(device.getDeviceXref(), device.getDeviceName(),
                device.getStatus().name(), Boolean.TRUE.equals(device.getIsDeleted()));
    }

    private static CertificateProfileSummary toProfileSummary(CertificateProfile profile) {
        return new CertificateProfileSummary(profile.getProfileXref(), profile.getName());
    }

    /**
     * ISSUED collapses ISSUED and ISSUED_PENDING_NOTIFICATION — neither is meaningfully different
     * to a viewer. Boundaries are deliberately {@code !isAfter} (inclusive) throughout, matching
     * {@link IotDeviceCertificateRepository#search}'s exclusive-after/inclusive-before bounds
     * exactly — the two must agree, or a row could match one {@code status} filter while
     * displaying a different one.
     */
    private String displayStatus(IotDeviceCertificate certificate, OffsetDateTime now) {
        String lifecycle = certificate.getStatus();
        if (!"ISSUED".equals(lifecycle) && !"ISSUED_PENDING_NOTIFICATION".equals(lifecycle)) {
            return lifecycle;
        }
        OffsetDateTime validTo = certificate.getValidTo();
        if (!validTo.isAfter(now)) {
            return "EXPIRED";
        }
        if (!validTo.isAfter(now.plusDays(DEFAULT_EXPIRING_WITHIN_DAYS))) {
            return "EXPIRING";
        }
        return "ISSUED";
    }

    private List<ScepCertificateIssuedMessage.SubjectAlternativeName> readSans(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored SAN JSON is invalid", exception);
        }
    }

    private List<String> readStringList(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored JSON is invalid", exception);
        }
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String normalizeCaProvider(String value) {
        String normalized = normalize(value);
        return normalized == null ? null : normalized.toUpperCase(Locale.ROOT);
    }
}
