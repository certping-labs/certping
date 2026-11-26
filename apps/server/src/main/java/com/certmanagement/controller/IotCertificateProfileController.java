// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.iot.dto.response.DeviceSourceEventDto;
import com.certmanagement.iot.profile.CertificateProfileResponse;
import com.certmanagement.iot.profile.CertificateProfileArchiveService;
import com.certmanagement.iot.profile.CertificateProfileService;
import com.certmanagement.iot.profile.CertificateProfileSyncService;
import com.certmanagement.iot.profile.CreateCertificateProfileRequest;
import com.certmanagement.iot.profile.ProfileControlMode;
import com.certmanagement.iot.profile.ProfileLifecycleStatus;
import com.certmanagement.iot.profile.ProviderSyncStatus;
import com.certmanagement.iot.profile.UpdateCertificateProfileRequest;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.iot.service.IotDeviceSourceService;
import com.certmanagement.security.GatewayRequestContext;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static com.certmanagement.security.Permissions.IOT_CERTIFICATE_PROFILE_MANAGE;
import static com.certmanagement.security.Permissions.IOT_CERTIFICATE_PROFILE_SYNC;
import static com.certmanagement.security.Permissions.IOT_CERTIFICATE_PROFILE_VIEW;

@RestController
@RequiredArgsConstructor
@FeatureGated(FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT)
@Tag(name = "Machine Identity Certificate Profiles",
        description = "DB-backed certificate delivery profiles and asynchronous provider synchronization.")
public class IotCertificateProfileController {
    private final CertificateProfileService profileService;
    private final CertificateProfileArchiveService archiveService;
    private final CertificateProfileSyncService syncService;
    private final IotDeviceSourceService sourceService;
    private final IotDeviceSourceEventService eventService;

    @GetMapping(Paths.IOT_CERTIFICATE_PROFILES)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_VIEW + "')")
    public Page<CertificateProfileResponse> list(
            @RequestParam(required = false) String sourceXref,
            @RequestParam(required = false) ProfileLifecycleStatus lifecycleStatus,
            @RequestParam(required = false) ProfileControlMode controlMode,
            @RequestParam(required = false) ProviderSyncStatus providerSyncStatus,
            @RequestParam(required = false) String targetPlatform,
            @RequestParam(required = false) String search,
            Pageable pageable) {
        return profileService.list(currentOrganizationId(), sourceXref, lifecycleStatus,
                controlMode, providerSyncStatus, targetPlatform, search, pageable);
    }

    @GetMapping(Paths.IOT_CERTIFICATE_PROFILE)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_VIEW + "')")
    public CertificateProfileResponse get(@PathVariable String profileXref) {
        return profileService.get(currentOrganizationId(), profileXref);
    }

    @GetMapping(Paths.IOT_CERTIFICATE_PROFILE_EVENTS)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_VIEW + "')")
    public Page<DeviceSourceEventDto> events(
            @PathVariable String profileXref, Pageable pageable) {
        Long organizationId = currentOrganizationId();
        var profile = profileService.requireProfile(organizationId, profileXref);
        var source = sourceService.requireById(organizationId, profile.getDeviceSourceId());
        return eventService.listForProfile(source, profileXref, pageable);
    }

    @PostMapping(Paths.IOT_CERTIFICATE_PROFILES)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_PROFILE_CREATED, name = "#request.name()")
    public ResponseEntity<CertificateProfileResponse> create(
            @Valid @RequestBody CreateCertificateProfileRequest request) {
        CertificateProfileResponse response = profileService.create(
                currentOrganizationId(), currentUserId(), request);
        HttpStatus status = response.providerSyncStatus() == ProviderSyncStatus.PENDING
                ? HttpStatus.ACCEPTED : HttpStatus.CREATED;
        return ResponseEntity.status(status).body(response);
    }

    @PutMapping(Paths.IOT_CERTIFICATE_PROFILE)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_PROFILE_UPDATED, target = "#profileXref")
    public ResponseEntity<CertificateProfileResponse> update(
            @PathVariable String profileXref,
            @Valid @RequestBody UpdateCertificateProfileRequest request) {
        CertificateProfileResponse response = profileService.update(
                currentOrganizationId(), currentUserId(), profileXref, request);
        HttpStatus status = response.providerSyncStatus() == ProviderSyncStatus.PENDING
                ? HttpStatus.ACCEPTED : HttpStatus.OK;
        return ResponseEntity.status(status).body(response);
    }

    @DeleteMapping(Paths.IOT_CERTIFICATE_PROFILE)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_MANAGE + "')")
    @AuditFailure(value = AuditEventType.IOT_PROFILE_DELETED, target = "#profileXref")
    public ResponseEntity<Void> archiveMissing(@PathVariable String profileXref) {
        archiveService.archiveMissing(
                currentOrganizationId(), currentUserId(), profileXref);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(Paths.IOT_SOURCE_PROFILE_SYNC)
    @PreAuthorize("hasPermission(null, '" + IOT_CERTIFICATE_PROFILE_SYNC + "')")
    public ResponseEntity<Map<String, String>> sync(@PathVariable String sourceXref) {
        String requestXref = syncService.request(
                currentOrganizationId(), sourceXref, currentUserId());
        return ResponseEntity.accepted().body(Map.of(
                "status", "ACCEPTED",
                "sourceXref", sourceXref,
                "requestXref", requestXref));
    }

    private static Long currentOrganizationId() {
        String value = GatewayRequestContext.getOrganizationId();
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "An organization context is required");
        }
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException exception) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Invalid organization context");
        }
    }

    private static Long currentUserId() {
        Integer value = GatewayRequestContext.getUserId();
        if (value == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Authentication is required");
        }
        return value.longValue();
    }
}
