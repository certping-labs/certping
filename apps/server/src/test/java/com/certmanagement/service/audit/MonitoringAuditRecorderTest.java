// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.entity.AlertEntity;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * The monitoring rows as they are stored: a monitor is named by its host, never its URL (which can carry a path,
 * a query or credentials); an alert row says read or unread; the agent's cadence change carries before and after.
 */
class MonitoringAuditRecorderTest {

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final MonitoringAuditRecorder monitoring = new MonitoringAuditRecorder(recorder);

    @BeforeEach
    void inAMembersRequest() {
        GatewayRequestContext.set(7, "42", "req-1", "jane@acme.test");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void anAlertIsMarkedReadOrUnread() {
        AlertEntity alert = AlertEntity.builder().id(11L).organizationId(42L).domain("example.com")
                .alertType(AlertTypeEnum.DEPLOYMENT_FAILURE).message("Azure said: vault example-vault-x denied")
                .errorDetail("stack trace").build();
        monitoring.alertMarked(alert, false);
        monitoring.alertMarked(alert, true);

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Marked the alert for example.com as read", "Marked the alert for example.com as unread");
        assertThat(rows.get(0).event()).isEqualTo("alert.updated");
        assertThat(rows.get(0).featureKey()).isEqualTo("ALERTS");
        assertThat(rows.get(0).details().attributes()).containsEntry("state", "READ")
                .containsEntry("alertType", "DEPLOYMENT_FAILURE");
        assertThat(rows).allSatisfy(row -> assertThat(row.toString()).doesNotContain("example-vault")
                .doesNotContain("stack trace"));
    }

    @Test
    void theAgentsHealthReportingRows() {
        monitoring.heartbeatCadenceChanged(42L, 5, 15);
        monitoring.deepCheckRequested(42L, "dhc-1");

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("agent_health.cadence_changed",
                "agent_health.deep_check_requested");
        assertThat(rows.get(0).summary()).isEqualTo("Changed how often the agent reports its health to every 15 minutes");
        assertThat(rows.get(0).details().changes())
                .containsExactly(new AuditChange("heartbeatCadenceMinutes", "5", "15"));
        assertThat(rows.get(1).summary()).isEqualTo("Started a deep health check of the agent");
        assertThat(rows.get(1).resourceRef()).isEqualTo("dhc-1");
        assertThat(rows).allSatisfy(row -> assertThat(row.featureKey()).isEqualTo("AGENT_HEALTH_MONITORING"));
    }


    private List<AuditEventRow> rows() {
        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).record(captor.capture());
        return captor.getAllValues();
    }
}
