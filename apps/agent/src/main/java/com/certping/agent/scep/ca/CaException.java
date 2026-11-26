// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

/** The CA backend refused or could not sign the CSR. Mapped to {@code CertRep FAILURE badRequest}. */
public class CaException extends Exception {
    public CaException(String message) {
        super(message);
    }

    public CaException(String message, Throwable cause) {
        super(message, cause);
    }
}
