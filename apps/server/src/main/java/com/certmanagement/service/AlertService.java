// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.alert.AlertResponse;
import com.certmanagement.entity.AlertEntity;
import com.certmanagement.enums.AlertSeverity;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.service.audit.MonitoringAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Alert business logic.
 *
 * <p>Supports organization-scoped and user-scoped alert ownership.
 * A row belongs to exactly one owner: organizationId XOR userId (enforced by DB constraint).
 *
 * <p>Alerts are written by {@link com.certmanagement.messaging.CertResponseProcessor}
 * on FAILED / AGENT_ERROR events and queried by {@link com.certmanagement.controller.AlertController}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AlertService {

    private final AlertRepository alertRepository;
    /** The alert rows of the audit trail, written in the change's transaction. */
    private final MonitoringAuditRecorder monitoringAudit;

    // ------------------------------------------------------------------ //
    //  Write
    // ------------------------------------------------------------------ //

    @Transactional
    public AlertEntity saveAlert(AlertEntity alert) {
        log.info("Saving alert: type={}, domain={}", alert.getAlertType(), alert.getDomain());
        return alertRepository.save(alert);
    }

    // ------------------------------------------------------------------ //
    //  Read
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public AlertResponse getAlerts(Integer userId, Long organizationId, AlertTypeEnum alertType) {
        validateOwnership(userId, organizationId);

        log.info("Fetching alerts — {}, alertType={}", ownerLogString(userId, organizationId), alertType);

        List<AlertEntity> alerts;
        if (organizationId != null) {
            alerts = alertType != null
                    ? alertRepository.findByOrganizationIdAndAlertTypeOrderByCreatedAtDesc(organizationId, alertType)
                    : alertRepository.findByOrganizationIdOrderByCreatedAtDesc(organizationId);
        } else {
            alerts = alertType != null
                    ? alertRepository.findByUserIdAndAlertTypeOrderByCreatedAtDesc(userId, alertType)
                    : alertRepository.findByUserIdOrderByCreatedAtDesc(userId);
        }

        List<AlertResponse.Alert> items = alerts.stream()
                .map(this::toAlertItem)
                .collect(Collectors.toList());

        return AlertResponse.builder().alerts(items).build();
    }

    // ------------------------------------------------------------------ //
    //  Update
    // ------------------------------------------------------------------ //

    @Transactional
    public AlertEntity updateAlert(Long alertId, Boolean unread, Integer userId, Long organizationId) {
        AlertEntity alert = alertRepository.findById(alertId)
                .orElseThrow(() -> new ResourceNotFoundException("Alert not found with id: " + alertId));

        // Ownership check — organization or user must own this alert
        if (organizationId != null && !organizationId.equals(alert.getOrganizationId())) {
            log.warn("Organization {} attempted to update alert {} owned by organization {}",
                    organizationId, alertId, alert.getOrganizationId());
            throw new ResourceNotFoundException("Alert not found with id: " + alertId);
        }
        if (organizationId == null && userId != null && !userId.equals(alert.getUserId())) {
            log.warn("Unauthorized alert update attempt for alert {}",
                    alertId);
            throw new ResourceNotFoundException("Alert not found with id: " + alertId);
        }

        boolean changed = unread != null && !unread.equals(alert.getUnread());
        alert.setUnread(unread != null ? unread : alert.getUnread());
        AlertEntity updated = alertRepository.save(alert);
        if (changed) {
            monitoringAudit.alertMarked(updated, unread);
        }
        log.info("Updated alert {} — unread={}", alertId, updated.getUnread());
        return updated;
    }

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //

    private AlertResponse.Alert toAlertItem(AlertEntity e) {
        AlertSeverity severity = e.getSeverity() != null ? e.getSeverity() : AlertSeverity.CRITICAL;
        return AlertResponse.Alert.builder()
                .id(e.getId())
            .alertType(e.getAlertType())
                .status(e.getStatus() != null ? e.getStatus().name() : null)
                .domain(e.getDomain())
                .createdAt(e.getCreatedAt())
                .message(e.getMessage())
                .correlationId(e.getCorrelationId())
                .severity(severity)
                .unread(e.getUnread())
                .build();
    }

    private void validateOwnership(Integer userId, Long organizationId) {
        if (userId == null && organizationId == null) {
            throw new BadRequestException(
                    "Neither userId nor organizationId is present in the request context — cannot look up alerts");
        }
    }

    private String ownerLogString(Integer userId, Long organizationId) {
        return organizationId != null ? "organizationId=" + organizationId : "userId=" + userId;
    }
}
