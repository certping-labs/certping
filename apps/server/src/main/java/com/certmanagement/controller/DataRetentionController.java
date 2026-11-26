// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.Paths;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.GlobalSettingsService;
import com.certmanagement.service.SoftDeletePurgeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;
/**
 * Manages soft-delete data retention settings and manual purge operations.
 *
 * <p>Org-admin endpoints:
 * <ul>
 *   <li>POST   /api/v1/organizations/{orgId}/purge-soft-deleted — trigger immediate purge</li>
 *   <li>GET    /api/v1/organizations/{orgId}/settings/soft-delete-retention — get org override</li>
 * </ul>
 *
 * <p>Super-admin endpoints:
 * <ul>
 *   <li>PUT    /api/v1/organizations/{orgId}/settings/soft-delete-retention — set org override</li>
 *   <li>GET    /api/v1/admin/settings/soft-delete-retention — get global setting</li>
 *   <li>PUT    /api/v1/admin/settings/soft-delete-retention — set global setting</li>
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Data Retention", description = "Soft-delete purge and retention settings")
public class DataRetentionController {

    private final GlobalSettingsService  globalSettingsService;
    private final SoftDeletePurgeService purgeService;

    // ── Org-admin: purge ──────────────────────────────────────────────────────

    @AuditFailure(value = AuditEventType.DATA_RETENTION_PURGED, target = "#orgId", organization = "#orgId")
    @PostMapping(Paths.ORG_PURGE_SOFT_DELETED)
    @PreAuthorize("hasPermission(#orgId, 'ORGANIZATION', '" + ORGANIZATION_MANAGE + "')"
            + " and @permissionGrantPolicy.mayAdministerOrganization(#orgId)")
    @Operation(summary = "Purge all soft-deleted records older than the retention period for an organization")
    public ResponseEntity<Map<String, Object>> purgeOrganization(@PathVariable Long orgId) {
        int days = globalSettingsService.resolveRetentionDays(orgId);
        SoftDeletePurgeService.PurgeResult result = purgeService.purgeOrganization(orgId, days);
        return ResponseEntity.ok(Map.of(
                "organizationId", orgId,
                "retentionDays", days,
                "totalHardDeleted", result.totalHardDeleted(),
                "details", Map.of(
                        "certificates", result.certificatesDeleted(),
                        "renewalSchedules", result.renewalScheduleDeleted(),
                        "manualIssuanceStates", result.manualIssuanceDeleted(),
                        "userDomainCerts", result.userDomainCertsDeleted(),
                        "credentials", result.credentialsDeleted(),
                        "users", result.usersDeleted(),
                        "alerts", result.alertsDeleted()
                )
        ));
    }

    // ── Org-admin: retention override ─────────────────────────────────────────

    @GetMapping(Paths.ORG_RETENTION_SETTINGS)
    @PreAuthorize("hasPermission(#orgId, 'ORGANIZATION', '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get the soft-delete retention override for an organization")
    public ResponseEntity<Map<String, Object>> getOrgRetention(@PathVariable Long orgId) {
        Integer override    = globalSettingsService.getOrgRetentionDaysOverride(orgId);
        int     effectiveDays = globalSettingsService.resolveRetentionDays(orgId);
        return ResponseEntity.ok(Map.of(
                "organizationId", orgId,
                "overrideDays", override != null ? override : "null",
                "effectiveDays", effectiveDays,
                "globalDays", globalSettingsService.getGlobalRetentionDays()
        ));
    }

    @AuditFailure(value = AuditEventType.DATA_RETENTION_CHANGED, target = "#orgId", organization = "#orgId")
    @PutMapping(Paths.ORG_RETENTION_SETTINGS)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Set (or clear) the soft-delete retention override for an organization",
            description = "SUPER_ADMIN only. The override may be shorter or longer than the global period, "
                    + "1 to 3650 days; null clears it.")
    public ResponseEntity<Map<String, Object>> setOrgRetention(
            @PathVariable Long orgId,
            @RequestBody Map<String, Object> body) {
        Object daysVal = body.get("days");
        Integer days;
        if (daysVal == null || "null".equals(String.valueOf(daysVal))) {
            days = null;
        } else {
            try {
                days = Integer.parseInt(String.valueOf(daysVal));
            } catch (NumberFormatException e) {
                return ResponseEntity.badRequest().body(
                        Map.of("error", "days must be a positive integer or null"));
            }
        }
        globalSettingsService.setOrgRetentionDaysOverride(orgId, days);
        return ResponseEntity.ok(Map.of(
                "organizationId", orgId,
                "overrideDays", days != null ? days : "null",
                "effectiveDays", globalSettingsService.resolveRetentionDays(orgId)
        ));
    }

    // ── Super-admin: global retention ─────────────────────────────────────────

    @GetMapping(Paths.ADMIN_RETENTION_SETTINGS)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Get the global soft-delete retention period")
    public ResponseEntity<Map<String, Object>> getGlobalRetention() {
        return ResponseEntity.ok(Map.of(
                "globalRetentionDays", globalSettingsService.getGlobalRetentionDays()
        ));
    }

    @AuditFailure(value = AuditEventType.PLATFORM_SETTING_CHANGED, name = "'soft_delete_retention_days'")
    @PutMapping(Paths.ADMIN_RETENTION_SETTINGS)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Set the global soft-delete retention period")
    public ResponseEntity<Map<String, Object>> setGlobalRetention(
            @RequestBody Map<String, Object> body) {
        Object daysVal = body.get("days");
        if (daysVal == null) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "days is required"));
        }
        int days;
        try {
            days = Integer.parseInt(String.valueOf(daysVal));
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "days must be a positive integer"));
        }
        Long userId = GatewayRequestContext.getUserId() != null
                ? GatewayRequestContext.getUserId().longValue() : null;
        globalSettingsService.setGlobalRetentionDays(days, userId);
        return ResponseEntity.ok(Map.of(
                "globalRetentionDays", days
        ));
    }
}
