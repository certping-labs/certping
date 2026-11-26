// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class FeatureFlagChangeAuditTest {

    @Mock private com.certmanagement.audit.AuditRecorder auditRecorder;
    @InjectMocks private FeatureFlagChangeAudit audit;

    @Test
    void theOperatorsReasonIsTrimmed() {
        audit.recordGlobal(3L, "DISCOVERY", true, false, "  incident 9  ");

        assertThat(explicitRow().details().attributes()).containsEntry("reason", "incident 9");
    }

    @Test
    void orgTypeChangeNamesTheOrgType() {
        audit.recordOrgType(8L, "B2B", "ALERTS", null, true, "beta");

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.event()).isEqualTo("feature.changed");
        assertThat(row.details().attributes()).containsEntry("level", "ORG_TYPE").containsEntry("orgType", "B2B");
    }

    @Test
    void reasonIsCappedSoOneNoteCannotBloatTheAuditRow() {
        String longReason = "x".repeat(FeatureFlagChangeAudit.MAX_REASON_LENGTH + 50);
        assertThat(FeatureFlagChangeAudit.normalizeReason(longReason))
                .hasSize(FeatureFlagChangeAudit.MAX_REASON_LENGTH);
        assertThat(FeatureFlagChangeAudit.normalizeReason("   ")).isNull();
    }

    @Test
    void aPlatformTransitionNamesTheAdministratorOrNoOne() {
        java.util.List<Map<String, Object>> items =
                java.util.List.of(Map.of("kind", "RUNNING_DISCOVERY_SCANS", "count", 3));
        audit.recordPlatformTransition(42L, "DISCOVERY", true, items, 9);
        audit.recordPlatformTransition(42L, "DISCOVERY", false, items, null);

        ArgumentCaptor<com.certmanagement.audit.AuditEventRow> rows =
                ArgumentCaptor.forClass(com.certmanagement.audit.AuditEventRow.class);
        verify(auditRecorder, org.mockito.Mockito.times(2)).record(rows.capture());
        assertThat(rows.getAllValues().get(0).details().attributes()).containsEntry("requestedBy", "9");
        assertThat(rows.getAllValues().get(1).event()).isEqualTo("feature.resumed");
        assertThat(rows.getAllValues().get(1).details().attributes()).doesNotContainKey("requestedBy");
    }

    @Test
    void aForcedPauseByARequiredFlagNamesItAsTheCause() {
        java.util.List<Map<String, Object>> items = java.util.List.of(Map.of("kind", "AUTO_RENEW_CERTS", "count", 2));
        audit.recordForcedPause(42L, "CERTIFICATE_RENEWAL", "DNS_CREDENTIALS", items, 9);

        assertThat(explicitRow().details().attributes()).containsEntry("cause", "DNS_CREDENTIALS");
    }

    @Test
    void aGlobalChangeIsAPlatformRowWithTheOperatorsReason() {
        audit.recordGlobal(3L, "DISCOVERY", true, false, "incident 9");

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.event()).isEqualTo("feature.changed");
        assertThat(row.visibility()).isEqualTo(com.certmanagement.audit.AuditVisibility.INTERNAL);
        assertThat(row.summary()).isEqualTo("Turned off the feature 'DISCOVERY'");
        assertThat(row.details().changes()).containsExactly(new com.certmanagement.audit.AuditChange("enabled", "true", "false"));
        assertThat(row.details().attributes()).containsEntry("level", "GLOBAL").containsEntry("reason", "incident 9");
    }

    @Test
    void anOrganizationsOverrideLandsInItsTrailWithoutTheOperatorsNote() {
        audit.recordOrganization(5L, 42L, "PQC_READINESS", null,
                new FeatureFlagChangeAudit.OverrideState(true, true), "internal note");

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.event()).isEqualTo("feature.changed");
        assertThat(row.visibility()).isEqualTo(com.certmanagement.audit.AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.summary()).isEqualTo("Turned on the feature 'PQC_READINESS'");
        assertThat(row.details().changes()).extracting("field").containsExactly("enabled", "adminLocked");
        assertThat(row.toString()).doesNotContain("internal note");
    }

    @Test
    void removingAnOverrideIsItsOwnEvent() {
        audit.recordOrganization(5L, 42L, "PQC_READINESS", new FeatureFlagChangeAudit.OverrideState(false, true),
                null, null);

        assertThat(explicitRow().summary()).isEqualTo("Removed the override of the feature 'PQC_READINESS'");
    }

    @Test
    void aBulkClearCountsWhatItCleared() {
        audit.recordClear(42L, "DISCOVERY", "RUNNING_DISCOVERY_SCANS", "CANCEL_ALL", 3);

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.event()).isEqualTo("feature.records_cleared");
        assertThat(row.summary()).isEqualTo("Cleared 3 records of the feature 'DISCOVERY'");
        assertThat(row.details().attributes()).containsEntry("kind", "RUNNING_DISCOVERY_SCANS")
                .containsEntry("action", "CANCEL_ALL");
    }

    @Test
    void aPauseIsCertPingActingWithItsItemsAndWhoseChangeTriggeredIt() {
        audit.recordPlatformTransition(42L, "CERTIFICATE_DEPLOYMENT", true,
                java.util.List.of(Map.of("kind", "DEPLOYMENTS", "label", "deployments", "count", 12)), 9);

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.event()).isEqualTo("feature.paused");
        assertThat(row.actorType()).isEqualTo(com.certmanagement.audit.AuditActorType.SYSTEM);
        assertThat(row.actorJob()).isEqualTo("feature-lifecycle-transitions");
        assertThat(row.actorUserId()).isNull();
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.summary())
                .isEqualTo("Paused 12 records because the feature 'CERTIFICATE_DEPLOYMENT' was turned off");
        assertThat(row.details().attributes()).containsEntry("items", "12 deployments").containsEntry("requestedBy", "9");
    }

    @Test
    void aBaselinePauseIsTheReconcilersWithItsCause() {
        audit.recordBaselinePause(42L, "DISCOVERY", "GLOBAL",
                java.util.List.of(Map.of("kind", "SCANS", "label", "scans", "count", 1)));

        com.certmanagement.audit.AuditEventRow row = explicitRow();
        assertThat(row.actorJob()).isEqualTo("feature-lifecycle-reconcile");
        assertThat(row.details().attributes()).containsEntry("cause", "GLOBAL").doesNotContainKey("requestedBy");
    }

    private com.certmanagement.audit.AuditEventRow explicitRow() {
        ArgumentCaptor<com.certmanagement.audit.AuditEventRow> row =
                ArgumentCaptor.forClass(com.certmanagement.audit.AuditEventRow.class);
        verify(auditRecorder).record(row.capture());
        return row.getValue();
    }
}
