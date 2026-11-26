// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditErasure;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.testing.Transactions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SoftDeletePurgeServiceTest {

    @Mock private GlobalSettingsService globalSettingsService;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private CertificateRepository certificateRepository;
    @Mock private CertManualIssuanceStateRepository manualIssuanceStateRepository;
    @Mock private RenewalScheduleRepository renewalScheduleRepository;
    @Mock private UserDomainCertRepository userDomainCertRepository;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private UserRepository userRepository;
    @Mock private CertificateEventRepository certificateEventRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private SchedulerExecutionPolicy executionPolicy;
    @Mock private AuditErasure auditErasure;
    @Spy private TransactionTemplate transactionTemplate = Transactions.inline();

    @Mock private com.certmanagement.service.audit.OrganizationAuditRecorder organizationAuditRecorder;

    @InjectMocks private SoftDeletePurgeService service;


    private void enableFlag() {
        // Both kill switches now live in the soft-delete-purge JobPolicy entry; stubs set the answer.
    }

    private void allowPurge() {
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true);
    }

    private void stubPurgeCounts(int n) {
        when(manualIssuanceStateRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(anyLong(), any())).thenReturn(n);
        when(renewalScheduleRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(anyLong(), any())).thenReturn(n);
        when(certificateRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(anyLong(), any())).thenReturn(n);
        when(userDomainCertRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(anyLong(), any())).thenReturn(n);
        when(credentialReferenceRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(anyLong(), any())).thenReturn(n);
        when(userRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(anyLong(), any())).thenReturn(n);
        when(alertRepository.hardDeleteByOrganizationIdAndCreatedAtBefore(anyLong(), any())).thenReturn(n);
    }

    @Test
    void purgeOrganization_aggregatesAllRepositoryCounts() {
        allowPurge();
        stubPurgeCounts(2);
        SoftDeletePurgeService.PurgeResult result = service.purgeOrganization(1L, 30);
        // 7 repositories × 2 = 14
        assertThat(result.totalHardDeleted()).isEqualTo(14);
        assertThat(result.usersDeleted()).isEqualTo(2);
        assertThat(result.alertsDeleted()).isEqualTo(2);
    }

    @Test
    void purgeAll_loopsEveryOrg() {
        allowPurge();
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L, 2L));
        when(globalSettingsService.resolveRetentionDays(anyLong())).thenReturn(30);
        stubPurgeCounts(1);

        SoftDeletePurgeService.GlobalPurgeResult result = service.purgeAll();

        // 2 orgs × 7 repos × 1 = 14
        assertThat(result.totalHardDeleted()).isEqualTo(14);
    }

    @Test
    void purgeAll_continuesWhenOneOrgFails() {
        allowPurge();
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L, 2L));
        when(globalSettingsService.resolveRetentionDays(1L)).thenThrow(new RuntimeException("boom"));
        when(globalSettingsService.resolveRetentionDays(2L)).thenReturn(30);
        stubPurgeCounts(1);

        SoftDeletePurgeService.GlobalPurgeResult result = service.purgeAll();
        // Only org 2 succeeds: 7 repos × 1 = 7
        assertThat(result.totalHardDeleted()).isEqualTo(7);
    }

    @Test
    void purgeOrganization_isRefusedWhileTheFeatureFlagIsOff() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(false);

        assertThatThrownBy(() -> service.purgeOrganization(1L, 30))
                .isInstanceOf(FeatureDisabledException.class)
                .extracting("featureKey").isEqualTo(FeatureFlags.SOFT_DELETE_PURGE);
        verifyNoInteractions(certificateRepository, userRepository, alertRepository);
    }

    @Test
    void purgeOrganization_isRefusedWhileTheStaticSwitchIsOff() {
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(false);

        assertThatThrownBy(() -> service.purgeOrganization(1L, 30))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certificateRepository, userRepository, alertRepository);
    }

    @Test
    void purgeAll_isRefusedWhileTheFeatureFlagIsOff() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(false);

        assertThatThrownBy(service::purgeAll).isInstanceOf(FeatureDisabledException.class);
        verify(organizationRepository, never()).findAllOrgIds();
    }

    @Test
    void runAutoPurge_stopsOnceWhenTheFlagIsSwitchedOffMidRun() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true, true, false);
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L, 2L, 3L));
        when(globalSettingsService.resolveRetentionDays(anyLong())).thenReturn(30);
        stubPurgeCounts(1);

        service.runAutoPurge();

        verify(certificateRepository).hardDeleteByOrganizationIdAndDeletedAtBefore(eq(1L), any(OffsetDateTime.class));
        verify(certificateRepository, never()).hardDeleteByOrganizationIdAndDeletedAtBefore(eq(2L), any());
        verify(globalSettingsService, never()).resolveRetentionDays(3L);
    }

    @Test
    void purgeAll_stopsOnceWhenTheFlagIsSwitchedOffMidRun() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true, true, false);
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L, 2L, 3L));
        when(globalSettingsService.resolveRetentionDays(anyLong())).thenReturn(30);
        stubPurgeCounts(1);

        SoftDeletePurgeService.GlobalPurgeResult result = service.purgeAll();

        assertThat(result.totalHardDeleted()).isEqualTo(7);
        verify(globalSettingsService, never()).resolveRetentionDays(3L);
    }

    @Test
    void runAutoPurge_disabledByStaticFlag_skips() {
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(false);
        service.runAutoPurge();
        verify(organizationRepository, never()).findAllOrgIds();
    }

    @Test
    void runAutoPurge_disabledByFeatureFlag_skips() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(false);
        service.runAutoPurge();
        verify(organizationRepository, never()).findAllOrgIds();
    }

    @Test
    void runAutoPurge_enabled_purgesAllOrgs() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true);
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L));
        when(globalSettingsService.resolveRetentionDays(1L)).thenReturn(30);
        stubPurgeCounts(1);

        service.runAutoPurge();

        verify(certificateRepository).hardDeleteByOrganizationIdAndDeletedAtBefore(eq(1L), any(OffsetDateTime.class));
    }

    @Test
    void runAutoPurge_perOrgFailure_isCaughtAndContinues() {
        enableFlag();
        when(executionPolicy.canRun("soft-delete-purge")).thenReturn(true);
        when(organizationRepository.findAllOrgIds()).thenReturn(List.of(1L));
        when(globalSettingsService.resolveRetentionDays(1L)).thenThrow(new RuntimeException("boom"));

        // Should not propagate.
        service.runAutoPurge();
        verify(globalSettingsService).resolveRetentionDays(1L);
    }

    @Test
    void purgeOrganization_erasesThePurgedMembersFromTheAuditTrailBeforeDeletingThem() {
        allowPurge();
        stubPurgeCounts(1);
        when(userRepository.findPurgeableUserIds(eq(7L), any())).thenReturn(List.of(11, 12));

        service.purgeOrganization(7L, 30);

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(auditErasure, userRepository);
        order.verify(auditErasure).eraseMembers(List.of(11, 12));
        order.verify(userRepository).hardDeleteByOrganizationIdAndUpdatedAtBefore(eq(7L), any());
    }

    // ── data_retention.purged ────────────────────────────────────────────

    @Test
    void aPurgeSomeoneAskedForIsRecordedWhateverItFound() {
        allowPurge();

        service.purgeOrganization(1L, 30);

        org.mockito.Mockito.verify(organizationAuditRecorder).recordsPurged(1L, 30, 0);
    }

    @Test
    void theNightlySweepRecordsOnlyAnOrganizationItPurgedSomethingFor() {
        allowPurge();
        stubPurgeCounts(1);
        try (com.certmanagement.audit.AuditScope scope =
                     com.certmanagement.audit.AuditScope.system("soft-delete-purge", 1L)) {
            service.purgeOrganization(1L, 30);
        }
        org.mockito.Mockito.verify(organizationAuditRecorder).recordsPurged(1L, 30, 7);

        org.mockito.Mockito.reset(manualIssuanceStateRepository, renewalScheduleRepository,
                certificateRepository, userDomainCertRepository, credentialReferenceRepository,
                userRepository, alertRepository);
        try (com.certmanagement.audit.AuditScope scope =
                     com.certmanagement.audit.AuditScope.system("soft-delete-purge", 2L)) {
            service.purgeOrganization(2L, 30);
        }
        org.mockito.Mockito.verify(organizationAuditRecorder, org.mockito.Mockito.never())
                .recordsPurged(org.mockito.ArgumentMatchers.eq(2L), org.mockito.ArgumentMatchers.anyInt(),
                        org.mockito.ArgumentMatchers.anyInt());
    }
}
