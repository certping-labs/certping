// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateProfileArchiveServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-08-25T00:00:00Z");

    @Mock private CertificateProfileRepository profileRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private FeatureFlagService featureFlagService;

    private CertificateProfileArchiveService service;

    @BeforeEach
    void setUp() {
        service = new CertificateProfileArchiveService(
                profileRepository, sourceRepository, eventService, featureFlagService,
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC), iotAudit);
    }

    @Test
    void missingProfileIsSoftDeletedAndItsHistoryIsKept() {
        CertificateProfile profile = profile(ProviderSyncStatus.NOT_FOUND);
        IotDeviceSource source = IotDeviceSource.builder()
                .id(10L).organizationId(42L).sourceXref("source-1").build();
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source));

        service.archiveMissing(42L, 7L, "profile-1");

        assertThat(profile.getLifecycleStatus()).isEqualTo(ProfileLifecycleStatus.ARCHIVED);
        assertThat(profile.getUpdatedByUserId()).isEqualTo(7L);
        verify(profileRepository).save(profile);
        verify(eventService).record(eq(source), eq(DeviceSourceEventType.PROFILE_ARCHIVED),
                eq("ARCHIVED"), any(), eq(NOW), eq("profile-1"), eq("profile-1:archived"));
        verify(profileRepository, never()).delete(profile);
        verify(iotAudit).profileDeleted(profile);
    }

    @Test
    void profileStillPresentInIntuneCannotBeDeleted() {
        CertificateProfile profile = profile(ProviderSyncStatus.IN_SYNC);
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));

        assertThatThrownBy(() -> service.archiveMissing(42L, 7L, "profile-1"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("confirmed missing");

        verify(profileRepository, never()).save(any());
        verify(eventService, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    private static CertificateProfile profile(ProviderSyncStatus syncStatus) {
        return CertificateProfile.builder()
                .id(100L)
                .profileXref("profile-1")
                .organizationId(42L)
                .deviceSourceId(10L)
                .providerProfileId("native-1")
                .lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                .providerSyncStatus(syncStatus)
                .build();
    }
}
