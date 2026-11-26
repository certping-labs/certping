// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.entity.AlertEntity;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Writes the monitoring events of the audit trail: an alert marked read or unread, and the agent's health
 * reporting changed or deep-checked.
 *
 * <p>Each is written in the change's own transaction ({@link AuditRecorder#record}, which requires one): it
 * commits and rolls back with the change. The row written here is the action's one customer row (the request
 * interceptor's row is an internal {@code api.request} row).
 */
@Component
public class MonitoringAuditRecorder {

    private final AuditRecorder recorder;

    public MonitoringAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    // ── Alerts ───────────────────────────────────────────────────────────

    /** {@code alert} was marked read ({@code unread} false) or unread; nothing is recorded when it already was. */
    public void alertMarked(AlertEntity alert, boolean unread) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("state", unread ? "UNREAD" : "READ");
        if (alert.getAlertType() != null) {
            attributes.put("alertType", alert.getAlertType().name());
        }
        recorder.record(AuditEvents.success(AuditEventType.ALERT_UPDATED, AuditSubject.builder()
                .organizationId(alert.getOrganizationId())
                .resourceId(alert.getId())
                .resourceRef(alert.getId() == null ? null : alert.getId().toString())
                .domain(alert.getDomain())
                .attributes(attributes)
                .build()));
    }

    // ── Agent health ─────────────────────────────────────────────────────

    /** The organization's agent heartbeat interval changed from {@code before} to {@code after} minutes. */
    public void heartbeatCadenceChanged(Long organizationId, Integer before, int after) {
        recorder.record(AuditEvents.success(AuditEventType.AGENT_HEALTH_CADENCE_CHANGED, AuditSubject.builder()
                .organizationId(organizationId)
                .resourceId(organizationId)
                .changes(List.of(new AuditChange("heartbeatCadenceMinutes", Objects.toString(before, null),
                        Integer.toString(after))))
                .build()));
    }

    /** A deep health check {@code deepCheckId} of the organization's agent was requested. */
    public void deepCheckRequested(Long organizationId, String deepCheckId) {
        recorder.record(AuditEvents.success(AuditEventType.AGENT_HEALTH_DEEP_CHECK_REQUESTED, AuditSubject.builder()
                .organizationId(organizationId)
                .resourceRef(deepCheckId)
                .build()));
    }
}
