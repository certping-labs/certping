// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalSettingsEntity;
import com.certmanagement.entity.Organization;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.GlobalSettingsRepository;
import com.certmanagement.repository.OrganizationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalSettingsServiceTest {

    @Mock private GlobalSettingsRepository globalSettingsRepository;
    @Mock private OrganizationRepository organizationRepository;

    @Mock private com.certmanagement.service.audit.OrganizationAuditRecorder organizationAuditRecorder;

    @InjectMocks private GlobalSettingsService service;

    @Test
    void getGlobalRetentionDays_validValue_returnsParsed() {
        when(globalSettingsRepository.findById("soft_delete_retention_days"))
                .thenReturn(Optional.of(GlobalSettingsEntity.builder().value("45").build()));
        assertThat(service.getGlobalRetentionDays()).isEqualTo(45);
    }

    @Test
    void getGlobalRetentionDays_missing_returnsDefault() {
        when(globalSettingsRepository.findById("soft_delete_retention_days")).thenReturn(Optional.empty());
        assertThat(service.getGlobalRetentionDays()).isEqualTo(30);
    }

    @Test
    void getGlobalRetentionDays_nonNumeric_returnsDefault() {
        when(globalSettingsRepository.findById("soft_delete_retention_days"))
                .thenReturn(Optional.of(GlobalSettingsEntity.builder().value("abc").build()));
        assertThat(service.getGlobalRetentionDays()).isEqualTo(30);
    }

    @Test
    void setGlobalRetentionDays_belowOne_throws() {
        assertThatThrownBy(() -> service.setGlobalRetentionDays(0, 1L))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class);
    }

    @Test
    void setGlobalRetentionDays_existingRowUpdated() {
        when(globalSettingsRepository.updateValue(eq("soft_delete_retention_days"), eq("60"), any(), eq(5L)))
                .thenReturn(1);
        service.setGlobalRetentionDays(60, 5L);
        verify(globalSettingsRepository, never()).save(any());
    }

    @Test
    void setGlobalRetentionDays_noRowUpdated_inserts() {
        when(globalSettingsRepository.updateValue(any(), any(), any(), any())).thenReturn(0);
        service.setGlobalRetentionDays(15, 5L);
        ArgumentCaptor<GlobalSettingsEntity> cap = ArgumentCaptor.forClass(GlobalSettingsEntity.class);
        verify(globalSettingsRepository).save(cap.capture());
        assertThat(cap.getValue().getValue()).isEqualTo("15");
        assertThat(cap.getValue().getKey()).isEqualTo("soft_delete_retention_days");
    }

    @Test
    void getOrgRetentionDaysOverride_returnsValue() {
        Organization org = Organization.builder().id(1L).softDeleteRetentionDays(99).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        assertThat(service.getOrgRetentionDaysOverride(1L)).isEqualTo(99);
    }

    @Test
    void getOrgRetentionDaysOverride_orgMissing_returnsNull() {
        when(organizationRepository.findById(1L)).thenReturn(Optional.empty());
        assertThat(service.getOrgRetentionDaysOverride(1L)).isNull();
    }

    @Test
    void setOrgRetentionDaysOverride_belowOne_throws() {
        assertThatThrownBy(() -> service.setOrgRetentionDaysOverride(1L, 0))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class);
    }

    @Test
    void setOrgRetentionDaysOverride_orgMissing_throwsNotFound() {
        when(organizationRepository.findById(1L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.setOrgRetentionDaysOverride(1L, 40))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void setOrgRetentionDaysOverride_nullClearsOverride() {
        Organization org = Organization.builder().id(1L).softDeleteRetentionDays(50).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        service.setOrgRetentionDaysOverride(1L, null);
        assertThat(org.getSoftDeleteRetentionDays()).isNull();
        verify(organizationRepository).save(org);
    }

    @Test
    void setOrgRetentionDaysOverride_validValue_saves() {
        Organization org = Organization.builder().id(1L).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        service.setOrgRetentionDaysOverride(1L, 45);
        assertThat(org.getSoftDeleteRetentionDays()).isEqualTo(45);
    }

    @Test
    void setOrgRetentionDaysOverride_mayBeShorterThanTheGlobalValue() {
        Organization org = Organization.builder().id(1L).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        service.setOrgRetentionDaysOverride(1L, 1);

        assertThat(org.getSoftDeleteRetentionDays()).isEqualTo(1);
        verify(globalSettingsRepository, never()).findById(any());
    }

    @Test
    void setOrgRetentionDaysOverride_aboveTheMaximum_throws() {
        assertThatThrownBy(() -> service.setOrgRetentionDaysOverride(1L, 3651))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessageContaining("between 1 and 3650");
        verify(organizationRepository, never()).save(any());
    }

    @Test
    void resolveRetentionDays_usesALongerOrgOverride() {
        Organization org = Organization.builder().id(1L).softDeleteRetentionDays(90).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        assertThat(service.resolveRetentionDays(1L)).isEqualTo(90);
    }

    @Test
    void resolveRetentionDays_keepsAShorterOrgOverride() {
        Organization org = Organization.builder().id(1L).softDeleteRetentionDays(7).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        assertThat(service.resolveRetentionDays(1L)).isEqualTo(7);
        verify(globalSettingsRepository, never()).findById(any());
    }

    @Test
    void resolveRetentionDays_fallsBackToGlobalWhenNoOverride() {
        Organization org = Organization.builder().id(1L).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        when(globalSettingsRepository.findById("soft_delete_retention_days"))
                .thenReturn(Optional.of(GlobalSettingsEntity.builder().value("12").build()));
        assertThat(service.resolveRetentionDays(1L)).isEqualTo(12);
    }

    // ── Audited changes ─────────────────────────────────────────────────

    @Test
    void theGlobalPeriodIsAnInternalPlatformSettingChange() {
        when(globalSettingsRepository.findById("soft_delete_retention_days")).thenReturn(Optional.of(
                GlobalSettingsEntity.builder().key("soft_delete_retention_days").value("30").build()));
        when(globalSettingsRepository.updateValue(any(), any(), any(), any())).thenReturn(1);

        service.setGlobalRetentionDays(60, 5L);

        verify(organizationAuditRecorder).platformSettingChanged("soft_delete_retention_days", "30", "60");
    }

    @Test
    void anOrganizationsPeriodIsRecordedInItsTrailWithBeforeAndAfter() {
        Organization org = Organization.builder().id(1L).softDeleteRetentionDays(50).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        service.setOrgRetentionDaysOverride(1L, 14);

        verify(organizationAuditRecorder).retentionChanged(1L, 50, 14);
    }

    @Test
    void aRefusedPeriodRecordsNothing() {
        assertThatThrownBy(() -> service.setOrgRetentionDaysOverride(1L, 0)).isInstanceOf(com.certmanagement.exception.BadRequestException.class);

        org.mockito.Mockito.verifyNoInteractions(organizationAuditRecorder);
    }
}
