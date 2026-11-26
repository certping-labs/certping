// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class SsoAuthenticationException extends RuntimeException {

    public SsoAuthenticationException(String message) {
        super(message);
    }

    public SsoAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
