// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * A credential request refused for a reason the audit trail names by a stable code ({@link #getCode()}), e.g.
 * {@code KV_URI_INVALID} for a malformed secret store location. Answered as a 400 with its message, like any
 * {@link BadRequestException}; the code, never the message, is what a failure row stores.
 */
public class CredentialRejectedException extends BadRequestException {

    /** The secret store location is missing, too long or malformed. */
    public static final String SECRET_HANDLE_INVALID = "KV_URI_INVALID";
    /** The pasted credential details do not match the provider's shape. */
    public static final String DETAILS_INVALID = "CREDENTIAL_DETAILS_INVALID";
    /** Active certificates still use the credential. */
    public static final String IN_USE = "CREDENTIAL_IN_USE";
    /** A DNS credential where a deployment one is needed, or the other way round. */
    public static final String TYPE_MISMATCH = "CREDENTIAL_TYPE_MISMATCH";
    /** The credential was deleted. */
    public static final String NOT_ACTIVE = "CREDENTIAL_NOT_ACTIVE";

    private final String code;

    public CredentialRejectedException(String code, String message) {
        super(message);
        this.code = code;
    }

    public CredentialRejectedException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
