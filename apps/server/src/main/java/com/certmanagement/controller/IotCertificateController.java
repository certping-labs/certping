// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.iot.certificate.CertificateDetail;
import com.certmanagement.iot.certificate.CertificateListItem;
import com.certmanagement.iot.certificate.DeviceSyncRequest;
import com.certmanagement.iot.certificate.DeviceSyncResponse;
import com.certmanagement.iot.certificate.IotCertificateNudgeService;
import com.certmanagement.iot.certificate.IotCertificateQueryService;
import com.certmanagement.iot.revocation.CreateIotRevocationRequest;
import com.certmanagement.iot.revocation.IotCertificateRevocationService;
import com.certmanagement.iot.revocation.IotRevocationResponse;
import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.security.GatewayRequestContext;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import static com.certmanagement.security.Permissions.IOT_DEVICE_MANAGE;
import static com.certmanagement.security.Permissions.IOT_DEVICE_VIEW;

/**
 * The certificate inventory: search, detail, and per-certificate history. Certificates are
 * sub-resources of device identity, so they share {@code IOT_DEVICE_VIEW} rather than a
 * dedicated permission — the same convention {@code IotDeviceController} already uses for
 * device events.
 *
 * <p>Deliberately not gated by {@code CA_EJBCA}/{@code CA_SMALLSTEP}: those flags control
 * whether a CA *integration* is currently active, not whether certificates it already issued
 * remain visible in inventory. Hiding already-issued certificates because an integration toggle
 * changed would be an audit/compliance regression, not a feature.
 */
@RestController
@RequiredArgsConstructor
@FeatureGated(FeatureFlags.IOT_DEVICE_MANAGEMENT)
@Tag(name = "IoT Certificates", description = "Device certificate inventory, detail, and history.")
public class IotCertificateController {

    private final IotCertificateQueryService certificateQueryService;
    private final IotCertificateNudgeService certificateNudgeService;
    private final IotCertificateRevocationService certificateRevocationService;

    @GetMapping(Paths.IOT_CERTIFICATES)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public Page<CertificateListItem> list(
            @RequestParam(required = false) String deviceXref,
            @RequestParam(required = false) String profileXref,
            @RequestParam(required = false) String sourceXref,
            @RequestParam(required = false) String caProvider,
            @RequestParam(required = false) IotCertificateQueryService.StatusFilter status,
            @RequestParam(required = false) Integer expiringWithinDays,
            @RequestParam(required = false) String renewalState,
            @RequestParam(required = false) String q,
            @PageableDefault(sort = "validTo", direction = Sort.Direction.ASC) Pageable pageable) {
        return certificateQueryService.list(currentOrganizationId(), deviceXref, profileXref,
                sourceXref, caProvider, status, expiringWithinDays, renewalState, q, pageable);
    }

    @GetMapping(Paths.IOT_CERTIFICATE)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public CertificateDetail get(@PathVariable String certificateXref) {
        return certificateQueryService.get(currentOrganizationId(), certificateXref);
    }

    /** Requests an Intune check-in for one, many, or every eligible linked device. */
    @PostMapping(Paths.IOT_CERTIFICATE_NUDGE)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_MANAGE + "')")
    public ResponseEntity<DeviceSyncResponse> nudge(
            @RequestParam(defaultValue = "false") boolean all,
            @Valid @RequestBody(required = false) DeviceSyncRequest request) {
        DeviceSyncResponse response = certificateNudgeService.requestDeviceSync(
                currentOrganizationId(), all, request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping(Paths.IOT_CERTIFICATE_REVOKE)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_CERTIFICATE_REVOKED, target = "#certificateXref")
    public ResponseEntity<IotRevocationResponse> revoke(
            @PathVariable String certificateXref,
            @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody CreateIotRevocationRequest request) {
        Integer userId = GatewayRequestContext.getUserId();
        IotRevocationResponse response = certificateRevocationService.request(
                currentOrganizationId(), certificateXref, idempotencyKey,
                userId == null ? null : userId.longValue(), request);
        return ResponseEntity.accepted().body(response);
    }

    @GetMapping(Paths.IOT_CERTIFICATE_HISTORY)
    @PreAuthorize("hasPermission(null, '" + IOT_DEVICE_VIEW + "')")
    public Page<DeviceEventDto> history(
            @PathVariable String certificateXref,
            @PageableDefault(sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return certificateQueryService.history(currentOrganizationId(), certificateXref, pageable);
    }

    private static Long currentOrganizationId() {
        String value = GatewayRequestContext.getOrganizationId();
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An organization context is required");
        }
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException exception) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid organization context");
        }
    }
}
