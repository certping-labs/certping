// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/**
 * The issuing CA could not make a temporary signing or revocation decision. Returning HTTP 503
 * keeps the SCEP transaction retryable; a definite CA rejection still uses a signed CertRep
 * failure through {@code CaException}.
 */
public class CaUnavailableException extends RuntimeException {
    public CaUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
