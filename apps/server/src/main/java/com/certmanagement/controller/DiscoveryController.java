// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.discovery.DiscoveredCertDto;
import com.certmanagement.dto.discovery.DiscoveredCertDetailDto;
import com.certmanagement.dto.discovery.DiscoveryRunResponse;
import com.certmanagement.dto.discovery.TriggerDiscoveryRequest;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.discovery.DiscoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.certmanagement.security.Permissions.CERTIFICATE_DELETE;
import static com.certmanagement.security.Permissions.CERTIFICATE_DEPLOY;
import static com.certmanagement.security.Permissions.CERTIFICATE_READ;

/**
 * Certificate discovery API: /api/v1/discovery/*
 *
 * <p>Trigger a discovery scan against a customer cloud target. The agent
 * processes the command and results arrive via CERT_DISCOVERY_RESPONSE), and
 * retrieve previously discovered certificates.
 *
 * <p>Gated by {@code DISCOVERY} (423 when off). Reads need {@code certificate:read}; starting a
 * scan needs {@code certificate:deploy}, because a scan has the agent sign in to the customer's
 * cloud with the same deployment credential a deploy uses; deleting a configuration needs
 * {@code certificate:delete}.
 */
@RestController
@FeatureGated(FeatureFlags.DISCOVERY)
@Validated
@RequiredArgsConstructor
@Tag(name = "Discovery", description = "Certificate discovery across cloud infrastructure targets")
public class DiscoveryController {

    private final DiscoveryService discoveryService;

    /**
     * Triggers a certificate discovery scan for the calling organization.
     *
     * <p>Async. Returns 202 Accepted immediately. The agent processes the discovery
     * command and upserts results into discovered_cert via CERT_DISCOVERY_RESPONSE.
     */
    @PostMapping(Paths.DISCOVERY_TRIGGER)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DEPLOY + "')")
    @Operation(summary = "Trigger certificate discovery",
               description = "Dispatches a CERT_DISCOVERY command to the agent for the given target type and credential.")
    @AuditFailure(value = AuditEventType.DISCOVERY_SCAN_STARTED, organization = "#organizationId")
    public ResponseEntity<DiscoveryRunResponse> triggerDiscovery(
            @Valid @RequestBody TriggerDiscoveryRequest request,
            @RequestParam(required = false) Long organizationId) {

        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        DiscoveryRunResponse response = discoveryService.triggerDiscovery(
                resolvedOrgId, request.getTargetType(), request.getCredentialXref());

        return ResponseEntity.accepted().body(response);
    }

    @GetMapping(Paths.DISCOVERY_TRIGGER)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "List discovery configurations",
               description = "Returns all saved discovery configurations for the organization with their latest run status.")
    public ResponseEntity<List<DiscoveryRunResponse>> listDiscoveryConfigs(
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        return ResponseEntity.ok(discoveryService.listDiscoveryConfigs(resolvedOrgId));
    }

    @PostMapping(Paths.DISCOVERY_TRIGGER_ALL)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DEPLOY + "')")
    @Operation(summary = "Run all saved certificate discovery configurations",
               description = "Dispatches discovery for every non-deleted saved configuration in the organization.")
    @AuditFailure(value = AuditEventType.DISCOVERY_SCAN_STARTED, organization = "#organizationId")
    public ResponseEntity<List<DiscoveryRunResponse>> triggerAllSavedDiscovery(
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        return ResponseEntity.accepted().body(discoveryService.triggerAllSavedDiscovery(resolvedOrgId));
    }

    @GetMapping(Paths.DISCOVERY_TRIGGER_CONFIG)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get discovery configuration status",
               description = "Returns the latest run status for one saved discovery configuration.")
    public ResponseEntity<DiscoveryRunResponse> getDiscoveryConfigStatus(
            @PathVariable Long configId,
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        return ResponseEntity.ok(discoveryService.getDiscoveryConfigStatus(resolvedOrgId, configId));
    }

    @PostMapping(Paths.DISCOVERY_TRIGGER_CONFIG)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DEPLOY + "')")
    @Operation(summary = "Run saved certificate discovery",
               description = "Uses one saved discovery configuration and returns the current run status.")
    @AuditFailure(value = AuditEventType.DISCOVERY_SCAN_STARTED, target = "#configId", organization = "#organizationId")
    public ResponseEntity<DiscoveryRunResponse> triggerSavedDiscovery(
            @PathVariable Long configId,
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        DiscoveryRunResponse response = discoveryService.triggerSavedDiscovery(resolvedOrgId, configId);
        return ResponseEntity.accepted().body(response);
    }

    @DeleteMapping(Paths.DISCOVERY_TRIGGER_CONFIG)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DELETE + "')")
    @Operation(summary = "Soft delete discovery configuration",
               description = "Marks one saved discovery configuration as deleted so it is no longer listed or triggered.")
    @AuditFailure(value = AuditEventType.DISCOVERY_CONFIG_DELETED, target = "#configId", organization = "#organizationId")
    public ResponseEntity<Void> deleteDiscoveryConfig(
            @PathVariable Long configId,
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        discoveryService.deleteDiscoveryConfig(resolvedOrgId, configId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Returns paginated discovered certificates for the calling organization.
     *
     * @param managed optional filter: true = CertPing-managed, false = externally managed,
     *                null = all
     * @param expiresWithinDays optional. Positive N restricts to certificates whose {@code notAfter}
     *                            falls between now (UTC) and now+N days (still valid, expiring soon).
     *                            Does not include already-expired certificates.
     */
    @GetMapping(Paths.DISCOVERY_CERTS)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "List discovered certificates",
               description = "Returns certificates discovered from cloud infrastructure targets. " +
                             "Filter by managed=true/false to see CertPing-managed vs external certs.")
    public ResponseEntity<Page<DiscoveredCertDto>> listDiscoveredCerts(
            @RequestParam(required = false) Long organizationId,
            @RequestParam(required = false) Boolean managed,
            @RequestParam(required = false) String domain,
            @RequestParam(required = false) String targetType,
            @RequestParam(required = false) String keyAlgorithm,
            @RequestParam(required = false) String certStatus,
            @RequestParam(required = false) Integer expiresWithinDays,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {

        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        Page<DiscoveredCertDto> results = discoveryService.listDiscoveredCerts(
                resolvedOrgId, managed, domain, targetType, keyAlgorithm, certStatus, expiresWithinDays,
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "discoveredAt")));

        return ResponseEntity.ok(results);
    }

    @GetMapping(Paths.DISCOVERY_CERT)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get discovered certificate details",
               description = "Returns common certificate fields and typed provider-specific discovery details.")
    public ResponseEntity<DiscoveredCertDetailDto> getDiscoveredCertificate(
            @PathVariable Long id,
            @RequestParam(required = false) Long organizationId) {
        Long resolvedOrgId = OrgResolver.resolve(organizationId);
        return ResponseEntity.ok(discoveryService.getDiscoveredCertificate(resolvedOrgId, id));
    }
}
