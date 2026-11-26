// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;

/** Soft-deletes provider profiles that a completed inventory proved are absent. */
@Service
@RequiredArgsConstructor
public class CertificateProfileArchiveService {
    private final CertificateProfileRepository profileRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceEventService eventService;
    private final FeatureFlagService featureFlagService;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    /**
     * Archives a missing profile without deleting its certificate history or provider snapshot.
     */
    @Transactional
    public void archiveMissing(Long organizationId, Long actorUserId, String profileXref) {
        assertFeatureFlags(organizationId);
        CertificateProfile profile = profileRepository
                .lockByProfileXrefAndOrganizationId(profileXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Certificate profile not found"));
        if (profile.getLifecycleStatus() == ProfileLifecycleStatus.ARCHIVED) {
            return;
        }
        if (profile.getProviderSyncStatus() != ProviderSyncStatus.NOT_FOUND) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Only a profile confirmed missing by a completed sync can be deleted");
        }
        IotDeviceSource source = sourceRepository.findById(profile.getDeviceSourceId())
                .filter(candidate -> organizationId.equals(candidate.getOrganizationId()))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.CONFLICT, "Device source is no longer available"));

        OffsetDateTime archivedAt = OffsetDateTime.now(clock);
        profile.setLifecycleStatus(ProfileLifecycleStatus.ARCHIVED);
        profile.setUpdatedByUserId(actorUserId);
        profileRepository.save(profile);
        iotAudit.profileDeleted(profile);
        eventService.record(source, DeviceSourceEventType.PROFILE_ARCHIVED, "ARCHIVED",
                Map.of("profileXref", profile.getProfileXref(),
                        "providerProfileId", profile.getProviderProfileId(),
                        "actorUserId", actorUserId),
                archivedAt, profileXref, profileXref + ":archived");
    }

    private void assertFeatureFlags(Long organizationId) {
        featureFlagService.assertEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId);
        featureFlagService.assertEnabled(
                FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, organizationId);
    }
}
