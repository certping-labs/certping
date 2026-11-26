// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.agent.CertificateAuthorityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.CREDENTIAL_READ;

/** The Certificate authorities view: every CA with its status, account metadata and credentials. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Certificate Authorities", description = "Which CAs the organization can issue from (metadata only)")
public class CertificateAuthorityController {

    private final CertificateAuthorityService certificateAuthorityService;

    @GetMapping(Paths.CERTIFICATE_AUTHORITIES)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_READ + "')")
    @Operation(summary = "List every certificate authority with its status",
            description = "Let's Encrypt and GlobalSign as the organization's agents report them; DigiCert "
                    + "from the organization's CA credentials. Never returns a key or secret.")
    public ResponseEntity<CertificateAuthoritiesResponse> list() {
        return ResponseEntity.ok(certificateAuthorityService.list(OrgResolver.fromJwt()));
    }
}
