// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.value.ValueSummaryDto;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.value.ValueSummaryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.CERTIFICATE_READ;

@RestController
@RequiredArgsConstructor
@Tag(name = "Value summary", description = "What CertPing automated for the organization and the work it saved")
public class ValueSummaryController {

    private final ValueSummaryService valueSummaryService;

    @GetMapping(Paths.CERTS_VALUE_SUMMARY)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Renewals, deployments and issuances CertPing ran, and the hours that saved")
    public ResponseEntity<ValueSummaryDto> valueSummary(@RequestParam(defaultValue = "365") int days) {
        if (days < 1 || days > 3650) {
            throw new BadRequestException("days must be between 1 and 3650");
        }
        return ResponseEntity.ok(valueSummaryService.summarize(OrgResolver.fromJwt(), days));
    }
}
