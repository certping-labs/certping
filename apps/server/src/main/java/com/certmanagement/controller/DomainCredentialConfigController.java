// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.DomainCredentialConfigResponse;
import com.certmanagement.dto.credconfig.EditDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.PatchDnsCredentialRequest;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.DomainCredentialConfigService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.certmanagement.security.Permissions.CERTIFICATE_ISSUE;

/**
 * REST API for managing domain credential configuration.
 *
 * Base path: /api/v1/certs/domains/{domain}/credential-config
 *
 * Changes to DNS credentials take effect on the next renewal only.
 * Adding a deployment target does NOT immediately deploy — use POST /certs/{xref}/deploy for that.
 */
@RestController
@RequestMapping(Paths.CERT_DOMAIN_CREDENTIAL_CONFIG)
@RequiredArgsConstructor
public class DomainCredentialConfigController {

    private final DomainCredentialConfigService configService;
    private final DnsCredentialAvailability dnsCredentialAvailability;

    /**
     * Updates the DNS credential for one domain key in dns_config.
     *
     * PATCH /api/v1/certs/domains/{domain}/credential-config/dns
     * Body: { "targetDomain": "example.org", "credentialXref": "cred-xref-b2" }
     */
    @PatchMapping("/dns")
    @AuditFailure(value = AuditEventType.DNS_CREDENTIAL_ASSIGNED, target = "#request.credentialXref",
            domain = "#request.targetDomain")
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    public ResponseEntity<DomainCredentialConfigResponse> patchDnsCredential(
            @PathVariable String domain,
            @Valid @RequestBody PatchDnsCredentialRequest request) {

        Long resolvedOrgId = OrgResolver.fromJwt();
        dnsCredentialAvailability.assertUsable(resolvedOrgId, List.of(request.getCredentialXref()));
        DomainCredentialConfigEntity updated =
                configService.patchDnsCredential(resolvedOrgId, domain,
                        request.getTargetDomain(), request.getCredentialXref());
        return ResponseEntity.ok(DomainCredentialConfigResponse.from(updated));
    }

    /**
     * Adds a deployment credentialXref to deployment_targets (idempotent).
     *
     * POST /api/v1/certs/domains/{domain}/credential-config/deployment-targets
     * Body: { "credentialXref": "cred-xref-deploy-3" }
     */
    @PostMapping("/deployment-targets")
    @AuditFailure(value = AuditEventType.DEPLOYMENT_TARGET_ADDED, target = "#request.credentialXref",
            domain = "#domain")
    @FeatureGated(FeatureFlags.CERTIFICATE_DEPLOYMENT)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    public ResponseEntity<DomainCredentialConfigResponse> addDeploymentTarget(
            @PathVariable String domain,
            @Valid @RequestBody AddDeploymentTargetRequest request) {

        Long resolvedOrgId = OrgResolver.fromJwt();
        DomainCredentialConfigEntity updated =
                configService.addDeploymentTarget(resolvedOrgId, domain, request);
        return ResponseEntity.ok(DomainCredentialConfigResponse.from(updated));
    }

    /**
     * Replaces the {@code targets} side of an already-added deployment target's envelope.
     * Preserves the {@code result} side so the next deploy is treated as a "subsequent"
     * deploy (re-import / PATCH at the provider against existing identifiers).
     *
     * <p>For Kubernetes, expects the legacy {@code config.nsSecretMap} payload. For other
     * providers, expects the generic {@code targets} JSON object.
     *
     * <p>PUT /api/v1/certs/domains/{domain}/credential-config/deployment-targets/{credentialXref}
     */
    @PutMapping("/deployment-targets/{credentialXref}")
    @AuditFailure(value = AuditEventType.DEPLOYMENT_TARGET_UPDATED, target = "#credentialXref", domain = "#domain")
    @FeatureGated(FeatureFlags.CERTIFICATE_DEPLOYMENT)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    public ResponseEntity<DomainCredentialConfigResponse> editDeploymentTarget(
            @PathVariable String domain,
            @PathVariable String credentialXref,
            @Valid @RequestBody EditDeploymentTargetRequest request) {

        Long resolvedOrgId = OrgResolver.fromJwt();
        DomainCredentialConfigEntity updated =
                configService.editDeploymentTarget(resolvedOrgId, domain, credentialXref, request);
        return ResponseEntity.ok(DomainCredentialConfigResponse.from(updated));
    }

    /**
     * Removes a deployment credentialXref from deployment_targets (idempotent). Not feature-gated, so
     * targets can still be cleared before switching deployment off or after it is off.
     *
     * DELETE /api/v1/certs/domains/{domain}/credential-config/deployment-targets/{credentialXref}
     */
    @DeleteMapping("/deployment-targets/{credentialXref}")
    @AuditFailure(value = AuditEventType.DEPLOYMENT_TARGET_REMOVED, target = "#credentialXref", domain = "#domain")
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    public ResponseEntity<DomainCredentialConfigResponse> removeDeploymentTarget(
            @PathVariable String domain,
            @PathVariable String credentialXref) {

        Long resolvedOrgId = OrgResolver.fromJwt();
        DomainCredentialConfigEntity updated =
                configService.removeDeploymentTarget(resolvedOrgId, domain, credentialXref);
        return ResponseEntity.ok(DomainCredentialConfigResponse.from(updated));
    }
}
