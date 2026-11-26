// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.CallerPermissions;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.cert.export.CertificateExportService;
import com.certmanagement.service.cert.export.ExportedCertificateFile;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.CERTIFICATE_READ;

/** Certificate export (download) — {@code POST /api/v1/certs/{certXref}/export}. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Cert Management", description = "Certificate lifecycle management")
public class CertExportController {

    /** Fixed so a parse error never echoes the body (which may hold the password) or Jackson's internals. */
    static final String UNREADABLE_BODY_MESSAGE =
            "The request body must be JSON with a string format, an optional string password and an "
                    + "optional boolean legacyPkcs12.";

    private final CertificateExportService certificateExportService;

    /**
     * POST rather than GET so the PKCS#12 password travels in the body, never in a URL or access log.
     * The response is the file itself and is never cached.
     */
    @PostMapping(Paths.CERTS_EXPORT)
    @FeatureGated(FeatureFlags.CERTIFICATE_DOWNLOAD)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Download a platform-stored certificate as PEM or PKCS#12")
    public ResponseEntity<byte[]> export(@PathVariable String certXref,
                                         @RequestBody(required = false) CertExportRequest request) {
        ExportedCertificateFile file = certificateExportService.export(OrgResolver.fromJwt(),
                GatewayRequestContext.getUserId(), CallerPermissions.current(), certXref, request);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(file.mediaType()))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(file.fileName()).build().toString())
                .cacheControl(CacheControl.noStore())
                .header("X-Content-Type-Options", "nosniff")
                .contentLength(file.content().length)
                .body(file.content());
    }

    /**
     * Malformed JSON or a wrongly typed field (e.g. {@code "legacyPkcs12": "yes"}) gets the export
     * error envelope with {@code INVALID_EXPORT_REQUEST}, like every other rejected export request,
     * instead of the generic 400 body.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> handleUnreadableBody(HttpMessageNotReadableException ex, HttpServletRequest request) {
        return GlobalExceptionHandler.certExportErrorResponse(
                CertExportException.invalidRequest(UNREADABLE_BODY_MESSAGE), request);
    }
}
