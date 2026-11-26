// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.profile.CertificateCorrelationResult;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Applies bounded, provider-proven certificate-to-profile outcomes after profile discovery. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateProfileCorrelationService {
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateSupersessionService supersessionService;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final CertificateProfileRepository profileRepository;
    private final IotDeviceEventService eventService;

    public void reconcile(
            IotDeviceSource source,
            String requestXref,
            List<CertificateCorrelationResult> results,
            OffsetDateTime occurredAt) {
        if (results.isEmpty()) {
            return;
        }
        List<String> certificateXrefs = results.stream()
                .map(CertificateCorrelationResult::certificateXref).toList();
        Map<String, IotDeviceCertificate> certificates = new HashMap<>();
        certificateRepository.findAllByDeviceSourceIdAndCertificateXrefIn(
                        source.getId(), certificateXrefs)
                .forEach(certificate -> certificates.put(
                        certificate.getCertificateXref(), certificate));

        List<String> providerProfileIds = results.stream()
                .filter(result -> "MATCHED".equals(result.status()))
                .map(CertificateCorrelationResult::providerProfileId)
                .distinct().toList();
        Map<ProfileKey, CertificateProfile> profiles = new HashMap<>();
        if (!providerProfileIds.isEmpty()) {
            profileRepository.findAllByDeviceSourceIdAndProviderProfileIdIn(
                            source.getId(), providerProfileIds)
                    .forEach(profile -> profiles.put(ProfileKey.of(
                            profile.getProviderProfileId(), profile.getProviderProfileType()), profile));
        }

        Map<Long, IotCertificateEnrollment> enrollments = new HashMap<>();
        List<Long> enrollmentIds = certificates.values().stream()
                .map(IotDeviceCertificate::getEnrollmentId).distinct().toList();
        enrollmentRepository.findAllById(enrollmentIds)
                .forEach(enrollment -> enrollments.put(enrollment.getId(), enrollment));

        List<IotDeviceCertificate> changedCertificates = new ArrayList<>();
        List<IotCertificateEnrollment> changedEnrollments = new ArrayList<>();
        for (CertificateCorrelationResult result : results) {
            IotDeviceCertificate certificate = certificates.get(result.certificateXref());
            if (!isPendingForSource(certificate, source)) {
                continue;
            }
            IotCertificateEnrollment enrollment = enrollments.get(certificate.getEnrollmentId());
            if (enrollment == null || !source.getId().equals(enrollment.getDeviceSourceId())
                    || enrollment.getProfileId() != null) {
                continue;
            }
            CertificateProfile profile = matchedProfile(result, profiles);
            if ("MATCHED".equals(result.status()) && profile == null) {
                log.warn("Deferring certificate profile match absent from completed discovery: "
                                + "sourceId={} certificateXref={} providerProfileId={}",
                        source.getId(), result.certificateXref(), result.providerProfileId());
                continue;
            }
            apply(certificate, enrollment, profile, result.status(), occurredAt);
            changedCertificates.add(certificate);
            changedEnrollments.add(enrollment);
            recordOutcome(enrollment, result, profile, requestXref, occurredAt);
        }
        if (!changedEnrollments.isEmpty()) {
            enrollmentRepository.saveAll(changedEnrollments);
            certificateRepository.saveAll(changedCertificates);
        log.info("Certificate profile correlation applied: source={} request={} results={} "
                        + "applied={}",
                source.getSourceXref(), requestXref, results.size(), changedCertificates.size());
        // The profile is the other half of a supersession pair: until it resolves, a replaced
        // certificate still looks current and keeps being asked to check in.
        changedCertificates.stream()
                .filter(certificate -> certificate.getDeviceId() != null
                        && certificate.getProfileId() != null)
                .map(certificate -> List.of(certificate.getOrganizationId(),
                        certificate.getDeviceId(), certificate.getProfileId()))
                .distinct()
                .forEach(group -> supersessionService.reconcileGroup(
                        (Long) group.get(0), (Long) group.get(1), (Long) group.get(2),
                        requestXref));
        }
    }

    private static boolean isPendingForSource(
            IotDeviceCertificate certificate, IotDeviceSource source) {
        return certificate != null && source.getId().equals(certificate.getDeviceSourceId())
                && certificate.getProfileId() == null;
    }

    private static CertificateProfile matchedProfile(
            CertificateCorrelationResult result,
            Map<ProfileKey, CertificateProfile> profiles) {
        if (!"MATCHED".equals(result.status())) {
            return null;
        }
        return profiles.get(ProfileKey.of(
                result.providerProfileId(), result.providerProfileType()));
    }

    private static void apply(
            IotDeviceCertificate certificate,
            IotCertificateEnrollment enrollment,
            CertificateProfile profile,
            String status,
            OffsetDateTime occurredAt) {
        Long profileId = profile == null ? null : profile.getId();
        certificate.setProfileId(profileId);
        certificate.setUpdatedAt(occurredAt);
        enrollment.setProfileId(profileId);
        enrollment.setProfileResolutionStatus(status);
        enrollment.setUpdatedAt(occurredAt);
    }

    private void recordOutcome(
            IotCertificateEnrollment enrollment,
            CertificateCorrelationResult result,
            CertificateProfile profile,
            String requestXref,
            OffsetDateTime occurredAt) {
        boolean matched = profile != null;
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("certificateXref", result.certificateXref());
        detail.put("resolutionStatus", result.status());
        if (matched) {
            detail.put("profileXref", profile.getProfileXref());
            detail.put("providerProfileId", result.providerProfileId());
            detail.put("matchMethod", result.matchMethod());
        }
        eventService.recordEnrollment(enrollment,
                matched ? DeviceEventType.CERTIFICATE_PROFILE_MATCHED
                        : DeviceEventType.CERTIFICATE_PROFILE_UNMATCHED,
                result.status(),
                matched ? "Certificate matched to its Intune profile"
                        : "Intune profile correlation did not produce one exact match",
                detail, requestXref,
                requestXref + ":profile-correlation:" + result.certificateXref(), occurredAt);
    }

    private record ProfileKey(String id, String type) {
        private static ProfileKey of(String id, String type) {
            return new ProfileKey(id, type == null ? null : type.toLowerCase(Locale.ROOT));
        }
    }
}
