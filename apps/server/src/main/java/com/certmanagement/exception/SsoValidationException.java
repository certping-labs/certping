// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when SSO token or signature validation fails.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class SsoValidationException extends RuntimeException {

    public SsoValidationException(String message) {
        super(message);
    }

    public SsoValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
