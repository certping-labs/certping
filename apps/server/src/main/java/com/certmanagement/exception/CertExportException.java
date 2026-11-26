// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * A refused certificate export. {@link GlobalExceptionHandler} renders it as the standard error
 * envelope plus {@code code}, and {@code reason} / {@code Retry-After} when set. Messages are shown
 * to the caller, so they never carry handles, key material or passwords.
 */
@Getter
public class CertExportException extends RuntimeException {

    public static final String INVALID_EXPORT_REQUEST = "INVALID_EXPORT_REQUEST";
    public static final String CERT_NOT_EXPORTABLE = "CERT_NOT_EXPORTABLE";
    public static final String CERT_MATERIAL_GONE = "CERT_MATERIAL_GONE";
    public static final String EXPORT_RATE_LIMITED = "EXPORT_RATE_LIMITED";
    public static final String CERT_MATERIAL_MISMATCH = "CERT_MATERIAL_MISMATCH";
    public static final String EXPORT_KEY_NOT_PERMITTED = "EXPORT_KEY_NOT_PERMITTED";

    private final HttpStatus status;
    private final String code;
    private final String reason;
    private final Long retryAfterSeconds;

    private CertExportException(HttpStatus status, String code, String reason, Long retryAfterSeconds,
                                String message) {
        super(message);
        this.status = status;
        this.code = code;
        this.reason = reason;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public static CertExportException invalidRequest(String message) {
        return new CertExportException(HttpStatus.BAD_REQUEST, INVALID_EXPORT_REQUEST, null, null, message);
    }

    public static CertExportException notExportable(String reason, String message) {
        return new CertExportException(HttpStatus.CONFLICT, CERT_NOT_EXPORTABLE, reason, null, message);
    }

    public static CertExportException materialGone(String message) {
        return new CertExportException(HttpStatus.GONE, CERT_MATERIAL_GONE, null, null, message);
    }

    public static CertExportException rateLimited(long retryAfterSeconds) {
        return new CertExportException(HttpStatus.TOO_MANY_REQUESTS, EXPORT_RATE_LIMITED, null, retryAfterSeconds,
                "Too many certificate exports. Try again later.");
    }

    /** 403: the format carries the private key and the caller lacks the permission that unlocks it. */
    public static CertExportException keyNotPermitted() {
        return new CertExportException(HttpStatus.FORBIDDEN, EXPORT_KEY_NOT_PERMITTED, null, null,
                "You can download the certificate and chain, but not the private key.");
    }

    public static CertExportException materialMismatch(String message) {
        return new CertExportException(HttpStatus.BAD_GATEWAY, CERT_MATERIAL_MISMATCH, null, null, message);
    }
}
