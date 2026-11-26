// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.iot.dto.response.DeviceDetail;
import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.iot.dto.response.DeviceListItem;
import com.certmanagement.iot.dto.response.IotSummary;
import com.certmanagement.iot.dto.response.DeviceSourceDto;
import com.certmanagement.iot.dto.response.DeviceSourceEventDto;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.service.IotDeviceArchiveService;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.iot.service.IotDeviceQueryService;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.iot.service.IotDeviceSourceService;
import com.certmanagement.iot.service.IotSyncOrchestrationService;
import com.certmanagement.iot.cahealth.CaConnectorResponse;
import com.certmanagement.iot.cahealth.IotCaHealthService;
import com.certmanagement.iot.certificate.CertificateListItem;
import com.certmanagement.iot.certificate.IotCertificateQueryService;
import com.certmanagement.security.GatewayRequestContext;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

import static com.certmanagement.security.Permissions.IOT_DEVICE_MANAGE;
import static com.certmanagement.security.Permissions.IOT_DEVICE_VIEW;
import static com.certmanagement.security.Permissions.IOT_SOURCE_MANAGE;
import static com.certmanagement.security.Permissions.IOT_SOURCE_VIEW;
import static com.certmanagement.security.Permissions.IOT_CA_HEALTH_VIEW;

/**
 * Single entry point for every {@code /api/v1/iot/...} endpoint — devices, their history,
 * and the device sources they come from. Sections mirror that grouping.
 *
 * <p>Auth: JWT via the server's {@code JwtAuthenticationFilter}; per-permission
 * {@code @PreAuthorize} guards enforced by {@code CustomPermissionEvaluator}. {@code userId}
 * and {@code organizationId} are never accepted on the wire — they come from the JWT via
 * {@link GatewayRequestContext}.
 *
 * <p>Read-only with respect to the MDM. Nothing here writes back to Intune, and the Entra
 * app is not granted the scopes that would allow it: wipe and retire are a deliberate
 * non-goal for this slice.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@FeatureGated(FeatureFlags.IOT_DEVICE_MANAGEMENT)
@Tag(name = "IoT Devices",
     description = "Device-source identity registry: inventory, source health, sync and history.")
public class IotDeviceController {

    private final IotDeviceQueryService deviceQueryService;
    private final IotDeviceArchiveService deviceArchiveService;
    private final IotDeviceSourceService sourceService;
    private final IotDeviceSourceEventService sourceEventService;
    private final IotDeviceEventService eventService;
    private final IotSyncOrchestrationService syncOrchestrationService;
    private final IotCaHealthService caHealthService;
    private final IotCertificateQueryService certificateQueryService;

    /** Pulls the verified userId from the JWT-derived request context, or 401s if missing. */
    private static Long currentUserId() {
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication is required");
        }
        return userId.longValue();
    }

    /** Pulls the verified organizationId from the JWT-derived request context. */
    private static Long currentOrganizationId() {
        String raw = GatewayRequestContext.getOrganizationId();
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An organization context is required");
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid organization context");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Devices
    // ═══════════════════════════════════════════════════════════════════════

    @GetMapping(Paths.IOT_DEVICES)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public ResponseEntity<Page<DeviceListItem>> listDevices(
            @RequestParam(required = false) String source,
            @RequestParam(required = false) DeviceStatus status,
            @RequestParam(required = false) ComplianceState complianceState,
            @RequestParam(required = false) String os,
            @RequestParam(required = false) String q,
            Pageable pageable) {

        return ResponseEntity.ok(deviceQueryService.list(
                currentOrganizationId(), source, status, complianceState, os, q, pageable));
    }

    @GetMapping(Paths.IOT_DEVICE_ID)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public ResponseEntity<DeviceDetail> getDevice(@PathVariable String deviceXref) {
        return ResponseEntity.ok(deviceQueryService.detail(currentOrganizationId(), deviceXref));
    }

    @GetMapping(Paths.IOT_DEVICE_EVENTS)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public ResponseEntity<Page<DeviceEventDto>> getDeviceEvents(@PathVariable String deviceXref,
                                                                Pageable pageable) {
        Long organizationId = currentOrganizationId();
        IotDevice device = deviceQueryService.requireByXref(organizationId, deviceXref);
        return ResponseEntity.ok(eventService.listForDevice(device.getId(), organizationId, pageable));
    }

    @GetMapping(Paths.IOT_DEVICE_CERTIFICATES)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public ResponseEntity<Page<CertificateListItem>> getDeviceCertificates(
            @PathVariable String deviceXref, Pageable pageable) {
        return ResponseEntity.ok(
                certificateQueryService.certificatesForDevice(currentOrganizationId(), deviceXref, pageable));
    }

    @PostMapping(Paths.IOT_DEVICE_DECOMMISSION)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_DEVICE_DECOMMISSIONED, target = "#deviceXref")
    public ResponseEntity<DeviceDetail> decommission(@PathVariable String deviceXref) {
        return ResponseEntity.ok(deviceQueryService.decommission(
                currentOrganizationId(), deviceXref, currentUserId()));
    }

    /**
     * Removes an orphaned device from the inventory. Nothing is deleted: the row, its certificates
     * and its history stay, and a device the source reports again returns on the next sync.
     */
    @PostMapping(Paths.IOT_DEVICE_ARCHIVE)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_DEVICE_ARCHIVED, target = "#deviceXref")
    public ResponseEntity<Void> archiveDevice(@PathVariable String deviceXref) {
        deviceArchiveService.archive(currentOrganizationId(), deviceXref, currentUserId());
        return ResponseEntity.noContent().build();
    }

    /** Puts an archived device back in the inventory. */
    @PostMapping(Paths.IOT_DEVICE_RESTORE)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_DEVICE_RESTORED, target = "#deviceXref")
    public ResponseEntity<Void> restoreDevice(@PathVariable String deviceXref) {
        deviceArchiveService.restore(currentOrganizationId(), deviceXref, currentUserId());
        return ResponseEntity.noContent().build();
    }

    @GetMapping(Paths.IOT_SUMMARY)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public ResponseEntity<IotSummary> summary() {
        return ResponseEntity.ok(deviceQueryService.summary(currentOrganizationId()));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Sources
    // ═══════════════════════════════════════════════════════════════════════

    @GetMapping(Paths.IOT_SOURCES)
    @PreAuthorize("hasPermission(null, '" + IOT_SOURCE_VIEW + "')")
    public ResponseEntity<List<DeviceSourceDto>> listSources() {
        return ResponseEntity.ok(sourceService.list(currentOrganizationId()));
    }

    @GetMapping(Paths.IOT_CA_CONNECTORS)
    @PreAuthorize("hasPermission(null, '" + IOT_CA_HEALTH_VIEW + "')")
    public ResponseEntity<List<CaConnectorResponse>> listCaConnectors() {
        return ResponseEntity.ok(caHealthService.list(currentOrganizationId()));
    }

    @GetMapping(Paths.IOT_CA_CONNECTOR)
    @PreAuthorize("hasPermission(null, '" + IOT_CA_HEALTH_VIEW + "')")
    public ResponseEntity<CaConnectorResponse> getCaConnector(@PathVariable String connectorId) {
        return ResponseEntity.ok(caHealthService.getByConnectorId(currentOrganizationId(), connectorId));
    }

    @GetMapping(Paths.IOT_SOURCE_EVENTS)
    @PreAuthorize("hasPermission(null, '" + IOT_SOURCE_VIEW + "')")
    public ResponseEntity<Page<DeviceSourceEventDto>> listSourceEvents(
            @PathVariable String sourceXref,
            @RequestParam(required = false) String correlationId,
            Pageable pageable) {
        var source = sourceService.requireByXref(currentOrganizationId(), sourceXref);
        return ResponseEntity.ok(sourceEventService.list(source, correlationId, pageable));
    }

    /**
     * Dispatches a full sync command to the agent.
     *
     * <p>202 rather than 200: the agent does the work asynchronously over the message queue and reports
     * back in pages, so nothing about the result is known when this returns.
     */
    @PostMapping(Paths.IOT_SOURCE_SYNC)
    @PreAuthorize("hasPermission(null, '" + IOT_SOURCE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_SOURCE_SYNC_STARTED, target = "#sourceXref")
    public ResponseEntity<Map<String, String>> triggerSync(@PathVariable String sourceXref) {
        Long organizationId = currentOrganizationId();
        Long userId = currentUserId();
        String syncXref = syncOrchestrationService.startManualSync(organizationId, sourceXref, userId);
        return ResponseEntity.accepted()
                .body(Map.of(
                        "status", "ACCEPTED",
                        "sourceXref", sourceXref,
                        "syncXref", syncXref));
    }

    @PostMapping(Paths.IOT_SOURCE_SYNC_STOP)
    @PreAuthorize("hasPermission(null, '" + IOT_SOURCE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_SOURCE_SYNC_STOPPED, target = "#sourceXref")
    public ResponseEntity<DeviceSourceDto> stopSync(@PathVariable String sourceXref) {
        return ResponseEntity.ok(sourceService.stopSync(
                currentOrganizationId(), sourceXref, currentUserId()));
    }
}
