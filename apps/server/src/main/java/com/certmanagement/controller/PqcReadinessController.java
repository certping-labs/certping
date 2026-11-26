// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.pqc.PqcReadinessReport;
import com.certmanagement.dto.pqc.PqcReadinessReport.CertDetail;
import com.certmanagement.dto.pqc.PqcReadinessReport.QuantumStatus;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.cbom.PqcReadinessService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.CERTIFICATE_READ;

@Slf4j
@RestController
@FeatureGated(FeatureFlags.PQC_READINESS)
@RequiredArgsConstructor
@Tag(name = "PQC Readiness", description = "Post-Quantum Cryptography readiness assessment for organisation certificates")
public class PqcReadinessController {

    private final PqcReadinessService pqcReadinessService;

    @GetMapping(Paths.PQC_READINESS)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get the PQC readiness summary for the organisation's certificates")
    public ResponseEntity<PqcReadinessReport> getPqcReadiness() {
        Long organizationId = OrgResolver.fromJwt();
        log.info("Generating PQC readiness summary for organization: {}", organizationId);
        return ResponseEntity.ok(pqcReadinessService.summary(organizationId));
    }

    @GetMapping(Paths.PQC_READINESS_CERTIFICATES)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "List the organisation's certificates with their PQC classification, paged")
    public ResponseEntity<Page<CertDetail>> listCertificates(
            @RequestParam(required = false) QuantumStatus quantumStatus,
            @PageableDefault(size = 15, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        Long organizationId = OrgResolver.fromJwt();
        return ResponseEntity.ok(pqcReadinessService.certificates(organizationId, quantumStatus, pageable));
    }
}
