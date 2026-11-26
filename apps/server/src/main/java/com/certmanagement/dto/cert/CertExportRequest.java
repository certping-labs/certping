// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Body of {@code POST /api/v1/certs/{certXref}/export}. Validated by
 * {@link com.certmanagement.service.cert.export.CertExportOptions#from} so every rejection carries
 * the {@code INVALID_EXPORT_REQUEST} code.
 *
 * @param format       FULLCHAIN_PEM, CERTIFICATE_PEM, CERTIFICATE_DER, PKCS7, PRIVATE_KEY_PEM or PKCS12
 * @param password     PKCS12 only: 8 to 128 characters; ignored for the other formats
 * @param legacyPkcs12 PKCS12 only: 3DES/SHA-1 protection for Windows Server 2016 and older or OpenSSL 1.0
 */
@Schema(description = "Certificate export request")
public record CertExportRequest(
        @Schema(example = "PKCS12") String format,
        @Schema(accessMode = Schema.AccessMode.WRITE_ONLY) String password,
        Boolean legacyPkcs12) {

    /** Never prints the password: request objects end up in logs and exception messages. */
    @Override
    public String toString() {
        return "CertExportRequest[format=" + format + ", password=" + (password == null ? "null" : "[REDACTED]")
                + ", legacyPkcs12=" + legacyPkcs12 + "]";
    }
}
