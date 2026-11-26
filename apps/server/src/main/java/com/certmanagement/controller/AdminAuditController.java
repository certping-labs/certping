// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditCategoryOption;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.audit.AuditedReads;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;
import com.certmanagement.dto.audit.AuditPlatformFilterRequest;
import com.certmanagement.dto.audit.AuditTrailPage;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.OrgResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.util.List;

import static com.certmanagement.security.Permissions.AUDIT_VIEW;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * The platform view of the audit trail: super admins
 * holding {@code audit:view} read every row, customer and internal, of one organization or of all.
 *
 * <ul>
 *   <li>Not clamped to the customers' 90-day window (retention bounds it), but one query spans at most 90 days;
 *       a request or correlation id search across every organization at most 7.</li>
 *   <li>Staff fields are shown: the person behind a support row, the address, user agent, authentication
 *       method, trace id, and a request row's route.</li>
 *   <li>Reading or exporting an organization's trail writes {@code support.audit_log_viewed} or
 *       {@code support.audit_log_exported} into that trail, which the customer reads as "Platform administrator"
 *       (views grouped every 15 minutes; every export its own row, written before any of its rows is read).</li>
 *   <li>Not feature-gated: {@code AUDIT_LOGS} is the customers' page, and support reads the trail whatever it
 *       says.</li>
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Audit Logs (platform)", description = "Every organization's audit trail, for platform administrators")
public class AdminAuditController {

    private static final String SUPER_ADMIN_WITH_AUDIT_VIEW =
            "hasRole('" + ROLE_SUPER_ADMIN + "') and hasPermission(null, '" + AUDIT_VIEW + "')";

    private final AuditTrailReader reader;
    private final AuditTrailExporter exporter;
    private final AuditVisibilityPolicy visibility;
    private final AuditedReads reads;

    @GetMapping(Paths.ADMIN_AUDIT_LOGS)
    @PreAuthorize(SUPER_ADMIN_WITH_AUDIT_VIEW)
    @Operation(summary = "Query every organization's audit trail",
               description = "Customer and internal rows (visibility=CUSTOMER or INTERNAL to narrow), of the "
                           + "organizationId named or of all. from defaults to 90 days before to (to: now); a range "
                           + "is at most 90 days, and a requestId or correlationId search without an organizationId "
                           + "at most 7. Newest first; follow nextCursor. Reading an organization's trail is "
                           + "recorded in it as support.audit_log_viewed.")
    public ResponseEntity<AuditTrailPage<AuditPlatformEntryDto>> queryPlatformAuditLogs(
            @Parameter(hidden = true) AuditPlatformFilterRequest filter,
            @Parameter(description = "Only 0: follow nextCursor") @RequestParam(required = false) Integer page,
            @Parameter(description = "Entries per page, at most 100") @RequestParam(required = false) Integer size) {
        AuditController.refusePage(page);
        AuditVisibilityPolicy.Viewer viewer = viewer(filter.getOrganizationId());
        AuditTrailPage<AuditPlatformEntryDto> result = reader.readPlatform(filter, size, viewer);
        reads.staffRead(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED, viewer.organizationId());
        return ResponseEntity.ok(result);
    }

    @GetMapping(Paths.ADMIN_AUDIT_LOGS_EXPORT)
    @PreAuthorize(SUPER_ADMIN_WITH_AUDIT_VIEW)
    @Operation(summary = "Export every organization's audit trail",
               description = "The rows the platform list's filters match, as csv (default) or json, at most 10,000 "
                           + "(400 EXPORT_TOO_LARGE: narrow the range) and 90 days. Exporting an organization's "
                           + "trail is recorded in it as support.audit_log_exported before any row is read, and "
                           + "refused (503 EXPORT_NOT_RECORDED) if that cannot be done.")
    public ResponseEntity<StreamingResponseBody> exportPlatformAuditLogs(
            @Parameter(hidden = true) AuditPlatformFilterRequest filter,
            @Parameter(description = "csv (default) or json") @RequestParam(required = false) String format) {
        return AuditController.attachment(exporter.exportPlatform(filter, format, viewer(filter.getOrganizationId())));
    }

    @GetMapping(Paths.ADMIN_AUDIT_LOGS_CATEGORIES)
    @PreAuthorize(SUPER_ADMIN_WITH_AUDIT_VIEW)
    @Operation(summary = "List every category to filter by",
               description = "Internal and Access categories included; enabled says whether the category is on for "
                           + "the organizationId named.")
    public ResponseEntity<List<AuditCategoryOption>> getPlatformCategories(
            @Parameter(description = "The organization the enabled flags are for") @RequestParam(required = false)
            String organizationId) {
        return ResponseEntity.ok(visibility.platformCategories(viewer(organizationId)));
    }

    @GetMapping(Paths.ADMIN_AUDIT_LOGS_ACTIONS)
    @PreAuthorize(SUPER_ADMIN_WITH_AUDIT_VIEW)
    @Operation(summary = "List every action code to filter by", description = "Internal ones included.")
    public ResponseEntity<List<String>> getPlatformActions() {
        requireSuperAdmin();
        return ResponseEntity.ok(visibility.platformActions());
    }

    @GetMapping(Paths.ADMIN_AUDIT_LOGS_RESOURCES)
    @PreAuthorize(SUPER_ADMIN_WITH_AUDIT_VIEW)
    @Operation(summary = "List every resource type to filter by", description = "Internal ones included.")
    public ResponseEntity<List<String>> getPlatformResources() {
        requireSuperAdmin();
        return ResponseEntity.ok(visibility.platformResourceTypes());
    }

    /** A super admin's view of the organization they name, or of every organization. */
    private AuditVisibilityPolicy.Viewer viewer(String organizationId) {
        requireSuperAdmin();
        Long requested = null;
        if (organizationId != null && !organizationId.isBlank()) {
            try {
                requested = Long.parseLong(organizationId.trim());
            } catch (NumberFormatException ex) {
                throw new BadRequestException("Invalid organizationId filter");
            }
            if (requested <= 0) {
                throw new BadRequestException("Invalid organizationId filter");
            }
        }
        return visibility.viewer(true, requested);
    }

    /** Defence in depth behind {@code @PreAuthorize}: the platform view is never a customer's. */
    private static void requireSuperAdmin() {
        if (!OrgResolver.isSuperAdmin()) {
            throw new AccessDeniedException("The platform audit log is for platform administrators");
        }
    }
}
