// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.OrgResolver;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.deployment.DeploymentQueryRequest;
import com.certmanagement.service.deployment.DeploymentQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.certmanagement.security.Permissions.DEPLOYMENTS_VIEW;

@RestController
@RequiredArgsConstructor
@Tag(name = "Deployments", description = "Deployment querying API")
public class DeploymentController {

    private final DeploymentQueryService deploymentQueryService;

    @GetMapping(Paths.DEPLOYMENTS_BASE)
    @FeatureGated(FeatureFlags.CERTIFICATE_DEPLOYMENT)
    @PreAuthorize("hasPermission(null, '" + DEPLOYMENTS_VIEW + "')")
    @Operation(summary = "Query deployments with optional filters",
               description = "Single endpoint supporting single lookup (requestId), list mode and summary mode")
    public ResponseEntity<Object> getDeployments(
            @ModelAttribute DeploymentQueryRequest filter,
            Pageable pageable) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        Pageable effectivePageable = pageable;
        if (pageable == null || pageable.getSort().isUnsorted()) {
            int pageNumber = pageable != null ? pageable.getPageNumber() : 0;
            int pageSize = pageable != null ? pageable.getPageSize() : 20;
            effectivePageable = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "updatedAt"));
        }
        return ResponseEntity.ok(deploymentQueryService.query(resolvedOrgId, filter, effectivePageable));
    }

    @GetMapping(Paths.DEPLOYMENTS_UDC_SUMMARY)
    @FeatureGated(FeatureFlags.CERTIFICATE_DEPLOYMENT)
    @PreAuthorize("hasPermission(null, '" + DEPLOYMENTS_VIEW + "')")
    @Operation(summary = "List user-domain certs with deployment summary",
            description = "Returns deployment requested/failed/succeeded counts grouped by user-domain certificate")
    public ResponseEntity<Map<String, Object>> getUserDomainCertDeploymentSummary(
            @RequestParam(required = false) String domain,
            @RequestParam(name = "userdomaincertificateid", required = false) Long userDomainCertId,
            @RequestParam(name = "excludeEmpty", defaultValue = "true") boolean excludeEmpty,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "domain"));
        return ResponseEntity.ok(
                deploymentQueryService.listUserDomainCertDeploymentSummary(
                        resolvedOrgId, domain, userDomainCertId, excludeEmpty, pageable));
    }

    @GetMapping(Paths.DEPLOYMENTS_CRED_CONFIG)
    @PreAuthorize("hasPermission(null, '" + DEPLOYMENTS_VIEW + "')")
    @Operation(summary = "Get deployment credential config by cert and credential xrefs",
            description = "Returns cert_deployment_config details for one certificate/deployment-credential pair")
    public ResponseEntity<Map<String, Object>> getDeploymentCredentialConfig(
            @RequestParam String certXref,
            @RequestParam(name = "deploymentCredentialXref") String deploymentCredentialXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        return ResponseEntity.ok(
                deploymentQueryService.getCredentialConfig(resolvedOrgId, certXref, deploymentCredentialXref));
    }
}
