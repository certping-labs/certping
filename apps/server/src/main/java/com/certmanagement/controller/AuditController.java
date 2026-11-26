// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.audit.AuditCategoryOption;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.audit.AuditedRead;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.audit.AuditAccessEntryDto;
import com.certmanagement.dto.audit.AuditAccessFilterRequest;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditEventPageResponse;
import com.certmanagement.dto.audit.AuditTrailPage;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.OrgResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.util.List;

import static com.certmanagement.security.Permissions.AUDIT_VIEW;

/**
 * The customer audit trail, read from {@code audit_events} ({@link AuditTrailReader}). Gated by
 * {@code AUDIT_LOGS} (423 while it is off; recording carries on) and {@code audit:view}.
 *
 * <p>{@code details} is a JSON string; {@code page}, {@code sort} and a super admin's {@code organizationId}
 * are honoured.
 *
 * <p>Beside the list: the export ({@code /export}, CSV or JSON, recorded as {@code audit_log.exported} before
 * any row is read, at most 10,000 rows and 10 exports an hour per organization), and the Access view
 * ({@code /access}, {@code /access/export}, {@code /access/activities}): the sensitive reads the list leaves out,
 * under the same window, cursor and page contract. Super admins read every organization's trail, internal rows
 * included, from {@link AdminAuditController}.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Audit Logs", description = "The organization's audit trail")
public class AuditController {

    private final AuditTrailReader reader;
    private final AuditVisibilityPolicy visibility;
    private final AuditTrailExporter exporter;

    @GetMapping(Paths.AUDIT_LOGS)
    @AuditedRead(value = AuditEventType.ACCESS_AUDIT_LOG_VIEWED, organization = "#filter.organizationId")
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "Query the audit trail",
               description = "Newest first; sort accepts timestamp only (timestamp,desc or timestamp,asc). "
                           + "Customers see the last 90 days (visibleFrom); an earlier from is clamped. "
                           + "Follow nextCursor for the next page; page is still accepted as an offset within "
                           + "the first 10,000 entries, but not together with cursor. The total is counted up to "
                           + "10,000: when totalElementsCapped is true it is a lower bound.")
    public ResponseEntity<AuditEventPageResponse> queryAuditLogs(
            @Parameter(hidden = true) AuditEventFilterRequest filter,
            @Parameter(description = "Offset page (0-based); prefer cursor") @RequestParam(required = false) Integer page,
            @Parameter(description = "Entries per page, at most 100") @RequestParam(required = false) Integer size,
            @Parameter(hidden = true) Sort sort) {
        AuditVisibilityPolicy.Viewer viewer = viewer(filter.getOrganizationId());
        return ResponseEntity.ok(reader.read(filter, page, size, ascending(sort), viewer));
    }

    @GetMapping(Paths.AUDIT_LOGS_EXPORT)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "Export the audit trail",
               description = "Every entry the list's filters match (format=csv, the default, or json), newest first, "
                           + "within the last 90 days. Sensitive reads are left out unless category=ACCESS. At most "
                           + "10,000 entries: a larger export is refused (400 EXPORT_TOO_LARGE) and the range or the "
                           + "filters must be narrowed. An organization makes at most 10 exports an hour (429 "
                           + "EXPORT_LIMIT, with Retry-After). Each export is recorded in the audit log before it "
                           + "starts, and refused (503 EXPORT_NOT_RECORDED) if that cannot be done.")
    public ResponseEntity<StreamingResponseBody> exportAuditLogs(
            @Parameter(hidden = true) AuditEventFilterRequest filter,
            @Parameter(description = "csv (default) or json") @RequestParam(required = false) String format,
            @Parameter(hidden = true) Sort sort) {
        filter.setOrganizationId(exportOrganization(filter.getOrganizationId()));
        AuditVisibilityPolicy.Viewer viewer = viewer(filter.getOrganizationId());
        return attachment(exporter.exportActivity(filter, format, ascending(sort), viewer));
    }

    @GetMapping(Paths.AUDIT_LOGS_ACCESS)
    @AuditedRead(value = AuditEventType.ACCESS_AUDIT_LOG_VIEWED, organization = "#filter.organizationId")
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "Query the Access view",
               description = "Who read something sensitive (an agent connection string, a CBOM, the audit log), "
                           + "newest first, within the last 90 days (visibleFrom). Reads by a platform administrator show "
                           + "as \"Platform administrator\". Follow nextCursor for the next page.")
    public ResponseEntity<AuditTrailPage<AuditAccessEntryDto>> queryAccessLogs(
            @Parameter(hidden = true) AuditAccessFilterRequest filter,
            @Parameter(description = "Only 0: follow nextCursor") @RequestParam(required = false) Integer page,
            @Parameter(description = "Entries per page, at most 100") @RequestParam(required = false) Integer size) {
        refusePage(page);
        return ResponseEntity.ok(reader.readAccess(filter, size, viewer(filter.getOrganizationId())));
    }

    @GetMapping(Paths.AUDIT_LOGS_ACCESS_EXPORT)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "Export the Access view",
               description = "As /export, for the Access view; recorded as access_log.exported, under the same "
                           + "limits.")
    public ResponseEntity<StreamingResponseBody> exportAccessLogs(
            @Parameter(hidden = true) AuditAccessFilterRequest filter,
            @Parameter(description = "csv (default) or json") @RequestParam(required = false) String format) {
        filter.setOrganizationId(exportOrganization(filter.getOrganizationId()));
        return attachment(exporter.exportAccess(filter, format, viewer(filter.getOrganizationId())));
    }

    /**
     * An export covers one organization. A super admin who names none exports the organization they work in, the
     * one the audit page shows, instead of being refused.
     */
    private static String exportOrganization(String requested) {
        if ((requested == null || requested.isBlank()) && OrgResolver.isSuperAdmin()) {
            Long working = OrgResolver.fromJwtOrNull();
            return working != null ? String.valueOf(working) : requested;
        }
        return requested;
    }

    @GetMapping(Paths.AUDIT_LOGS_ACCESS_ACTIVITIES)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "List the kinds of read the Access view filters by",
               description = "Event keys such as access.agent_connection_viewed, without those of features that are "
                           + "off for the organization (super admins see all).")
    public ResponseEntity<List<String>> getAccessActivities(
            @Parameter(description = "Super admins only") @RequestParam(required = false) String organizationId) {
        return ResponseEntity.ok(visibility.accessActivities(viewer(organizationId)));
    }

    @GetMapping(Paths.AUDIT_LOGS_CATEGORIES)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "List the categories to filter by",
               description = "Categories of features that are off for the organization are left out; super admins "
                           + "see every category, with enabled saying whether it is on for the organization.")
    public ResponseEntity<List<AuditCategoryOption>> getCategories(
            @Parameter(description = "Super admins only") @RequestParam(required = false) String organizationId) {
        return ResponseEntity.ok(visibility.categories(viewer(organizationId)));
    }

    @GetMapping(Paths.AUDIT_LOGS_RESOURCES)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "List the resource types to filter by",
               description = "The resource types of the audit catalog, without those of features that are off "
                           + "for the organization (super admins see all).")
    public ResponseEntity<List<String>> getAvailableResources(
            @Parameter(description = "Super admins only") @RequestParam(required = false) String organizationId) {
        return ResponseEntity.ok(visibility.resourceTypes(viewer(organizationId)));
    }

    @GetMapping(Paths.AUDIT_LOGS_ACTIONS)
    @FeatureGated(FeatureFlags.AUDIT_LOGS)
    @PreAuthorize("hasPermission(null, '" + AUDIT_VIEW + "')")
    @Operation(summary = "List the action codes to filter by",
               description = "The action codes of the audit catalog, without those of features that are off "
                           + "for the organization (super admins see all).")
    public ResponseEntity<List<String>> getAvailableActions(
            @Parameter(description = "Super admins only") @RequestParam(required = false) String organizationId) {
        return ResponseEntity.ok(visibility.actions(viewer(organizationId)));
    }

    /**
     * Who reads which trail: a super admin the organization they name (every organization when they name
     * none); anyone else their own, refusing another.
     */
    private AuditVisibilityPolicy.Viewer viewer(String organizationId) {
        Long requested = null;
        if (organizationId != null && !organizationId.isBlank()) {
            try {
                requested = Long.parseLong(organizationId.trim());
            } catch (NumberFormatException ex) {
                throw new BadRequestException("Invalid organizationId filter");
            }
        }
        Long effective = OrgResolver.resolveOptional(requested);
        return visibility.viewer(OrgResolver.isSuperAdmin(), effective);
    }

    /**
     * An export as a download: its type, its file name for the browser to save it under, and the rows it holds
     * ({@code X-Audit-Export-Rows}), so a client can tell an export that ended short.
     */
    static ResponseEntity<StreamingResponseBody> attachment(AuditTrailExporter.AuditExport export) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, export.contentDisposition())
                .header(AuditTrailExporter.AuditExport.ROWS_HEADER, String.valueOf(export.rows()))
                .contentType(export.contentType())
                .body(export.body());
    }

    /** The newer views page by cursor only: an offset would rescan every earlier row. */
    static void refusePage(Integer page) {
        if (page != null && page != 0) {
            throw new BadRequestException("page is not supported: follow nextCursor for the next page");
        }
    }

    /** Only the timestamp is a sort key (the index's); anything else keeps newest first. */
    private static boolean ascending(Sort sort) {
        if (sort == null) {
            return false;
        }
        Sort.Order byTimestamp = sort.getOrderFor("timestamp");
        return byTimestamp != null && byTimestamp.isAscending();
    }
}
