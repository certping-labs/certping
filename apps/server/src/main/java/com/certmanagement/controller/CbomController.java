// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.cbom.CbomProjectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditedRead;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

import static com.certmanagement.security.Permissions.CERTIFICATE_READ;

@Slf4j
@RestController
@FeatureGated(FeatureFlags.PQC_READINESS)
@RequiredArgsConstructor
@Tag(name = "CBOM", description = "Cryptographic Bill of Materials (CycloneDX 1.6)")
public class CbomController {

    private final CbomProjectionService cbomProjectionService;

    @GetMapping(value = Paths.CBOM_DOWNLOAD, produces = MediaType.APPLICATION_JSON_VALUE)
    @AuditedRead(AuditEventType.ACCESS_CBOM_DOWNLOADED)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Generate and download CBOM for organization's certificates (CycloneDX 1.6)")
    public void downloadCbom(HttpServletResponse response) throws IOException {
        Long organizationId = OrgResolver.fromJwt();
        log.info("Streaming CBOM for organization: {}", organizationId);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cbom.json\"");
        cbomProjectionService.writeCbom(organizationId, response.getOutputStream());
    }
}
