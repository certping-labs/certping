// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/**
 * A retry arrived with the same {@code transactionID} but a different CSR — a genuine conflict, not an
 * idempotent replay. It is surfaced as HTTP 409 because the transaction identifier conflicts with
 * server state and the request never reaches a SCEP issuance decision.
 */
public class ScepConflictException extends RuntimeException {
    public ScepConflictException(String message) {
        super(message);
    }
}
