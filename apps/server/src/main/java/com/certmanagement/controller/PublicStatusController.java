// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.status.StatusSummary;
import com.certmanagement.service.status.PublicStatusBoard;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The status page document: anonymous and served from the last completed checks, so traffic never
 * reaches a dependency. No rate limiter, because a Redis outage must not turn into a status failure.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Public Status", description = "Anonymous service status in the Statuspage summary shape")
public class PublicStatusController {

    static final String CACHE_CONTROL = "public, max-age=" + PublicStatusBoard.CHECK_INTERVAL.toSeconds();

    private final PublicStatusBoard board;

    @GetMapping(value = Paths.PUBLIC_STATUS, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Current state of CertPing's public components",
            description = "Public, no authentication. A subset of the Statuspage v2 summary document; "
                    + "component ids are stable. Checks run every 30 seconds.")
    @ApiResponse(responseCode = "200", description = "The component states, including outages",
            content = @Content(schema = @Schema(implementation = StatusSummary.class)))
    @ApiResponse(responseCode = "503", description = "This instance has not completed its first check yet")
    public ResponseEntity<StatusSummary> status() {
        return board.summary()
                .map(summary -> ResponseEntity.ok()
                        .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(summary))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .cacheControl(CacheControl.noStore())
                        .build());
    }
}
