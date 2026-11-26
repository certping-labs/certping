// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/** Lets the Platform Super Admin read exactly what opt-in telemetry sends, and whether it is on. */
@RestController
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin/telemetry")
@Tag(name = "Telemetry", description = "Opt-in usage reporting: status and the report it would send")
@SecurityRequirement(name = "bearer-jwt")
public class TelemetryController {

    private final TelemetryService telemetryService;
    private final TelemetryProperties properties;

    @Operation(summary = "Whether telemetry is on, where it reports, and the report it would send now")
    @GetMapping
    public Map<String, Object> status() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", telemetryService.enabled());
        body.put("endpoint", properties.getEndpoint());
        body.put("interval", properties.getInterval().toString());
        body.put("report", telemetryService.preview());
        return body;
    }
}
