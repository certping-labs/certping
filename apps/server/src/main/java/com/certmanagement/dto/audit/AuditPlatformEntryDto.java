// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * One entry of the platform view ({@code GET /api/v1/admin/audit-logs}): every field of the customer entry,
 * unmasked (staff rows show the person, their address and user agent), then what only the platform sees:
 * the visibility, the actor as one stable string, the authentication method, the trace id and, on a request
 * row, the request.
 */
@Schema(description = "A platform audit entry: a customer entry with the staff fields")
public record AuditPlatformEntryDto(
        @JsonUnwrapped AuditEventEntryDto entry,
        @Schema(description = "CUSTOMER (in the organization's trail) or INTERNAL (the platform's only)",
                example = "CUSTOMER") String visibility,
        @Schema(description = "The actor as one stable string: user:42, system:<job> or anonymous", example = "user:42")
        String actor,
        @Schema(description = "A super admin acting in another organization's trail (customers read it as "
                + "\"Platform administrator\")", example = "false") boolean staff,
        @Schema(description = "How the actor signed in", example = "PASSWORD", nullable = true) String authMethod,
        @Schema(description = "OpenTelemetry trace id", example = "4bf92f3577b34da6a3ce929d0e0e4736", nullable = true)
        String traceId,
        @Schema(description = "The request, on a request row (api.request): its route pattern, never the raw path",
                nullable = true) RequestInfo request) {

    /** A mutating request by its route pattern; never its raw path or query values. */
    @Schema(description = "A request by its route pattern")
    public record RequestInfo(
            @Schema(example = "POST") String method,
            @Schema(example = "/api/v1/credentials/{id}") String route,
            @Schema(example = "201") Integer status,
            @Schema(example = "84") Long durationMs) {
    }
}
