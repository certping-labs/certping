// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.dto.alert.AlertResponse;
import com.certmanagement.dto.alert.UpdateAlertRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.AlertService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.certmanagement.security.Permissions.*;

/**
 * Alert API.
 *
 * <p>Alerts are written by {@link com.certmanagement.messaging.CertResponseProcessor}
 * on FAILED / AGENT_ERROR events. This controller exposes them for UI consumption.
 *
 * <p>Ownership is resolved from the JWT context (organizationId when present, otherwise userId).
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Alerts", description = "In-app cert lifecycle alerts")
@SecurityRequirement(name = "bearerAuth")
public class AlertController {

    private final AlertService alertService;

    // ------------------------------------------------------------------ //
    //  GET /api/v1/alerts
    // ------------------------------------------------------------------ //

    @GetMapping(Paths.ALERTS)
    @FeatureGated(FeatureFlags.ALERTS)
    @PreAuthorize("hasPermission(null, '" + ALERTS_VIEW + "')")
    @Operation(summary = "List alerts for the calling user or organization")
    public ResponseEntity<AlertResponse> getAlerts(
            @RequestParam(value = "alertType", required = false) AlertTypeEnum alertType) {
        Integer userId = GatewayRequestContext.getUserId();
        Long organizationId = OrgResolver.fromJwtOrNull();

        log.info("GET alerts request received, alertType={}", alertType);

        AlertResponse response = alertService.getAlerts(userId, organizationId, alertType);
        return ResponseEntity.ok(response);
    }

    // ------------------------------------------------------------------ //
    //  PATCH /api/v1/alerts/{id}
    // ------------------------------------------------------------------ //

    @PatchMapping(Paths.ALERTS_ID)
    @FeatureGated(FeatureFlags.ALERTS)
    @PreAuthorize("hasPermission(null, '" + ALERTS_UPDATE + "')")
    @Operation(summary = "Mark an alert as read or unread")
    @AuditFailure(value = AuditEventType.ALERT_UPDATED, target = "#id")
    public ResponseEntity<Map<String, Object>> updateAlert(
            @Parameter(description = "Alert ID") @PathVariable Long id,
            @RequestBody UpdateAlertRequest request) {

        Integer userId = GatewayRequestContext.getUserId();
        Long organizationId = OrgResolver.fromJwtOrNull();

        log.info("PATCH alert id={} — unread={}", id, request.getUnread());

        alertService.updateAlert(id, request.getUnread(), userId, organizationId);

        return ResponseEntity.ok(Map.of("success", true, "alertId", id));
    }
}
