// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.audit.AuditRetentionService;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.audit.AuditRetentionResponse;
import com.certmanagement.dto.audit.AuditRetentionUpdateRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * How long audit events are kept, platform-wide: super admin only ({@link AuditRetentionService}).
 * <ul>
 *   <li>GET /api/v1/admin/settings/audit-retention: the period, its bounds, and when and from which month the
 *       next retention run applies it</li>
 *   <li>PUT /api/v1/admin/settings/audit-retention {@code {months, reason}}: confirms the period, changing it
 *       first when it differs; 6 to 36 months, else 400 {@code AUDIT_RETENTION_OUT_OF_RANGE}; the reason is
 *       required. Nothing is deleted before the first confirmation, nor by the request: the first confirmation
 *       and a shorter period take effect at {@code effectiveFrom}, after a day's grace</li>
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Audit Retention", description = "How long audit events are kept")
public class AuditRetentionController {

    private final AuditRetentionService retentionService;

    @GetMapping(Paths.ADMIN_AUDIT_RETENTION_SETTINGS)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Get how long audit events are kept")
    public ResponseEntity<AuditRetentionResponse> getAuditRetention() {
        return ResponseEntity.ok(retentionService.view());
    }

    @AuditFailure(value = AuditEventType.AUDIT_RETENTION_CHANGED, name = "'audit_retention_months'")
    @PutMapping(Paths.ADMIN_AUDIT_RETENTION_SETTINGS)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Confirm (and optionally change) how long audit events are kept",
            description = "SUPER_ADMIN only. 6 to 36 months, with a reason (1 to 500 characters) kept in the"
                    + " platform's own trail. Every save confirms the period, even unchanged; nothing is deleted"
                    + " before the first confirmation. Months are dropped whole, so rows are kept up to one month"
                    + " longer. The first confirmation and a shorter period delete nothing now: they take effect"
                    + " at effectiveFrom, after a day's grace.")
    public ResponseEntity<AuditRetentionResponse> setAuditRetention(
            @Valid @RequestBody AuditRetentionUpdateRequest request) {
        return ResponseEntity.ok(retentionService.update(request.months(), request.reason()));
    }
}
