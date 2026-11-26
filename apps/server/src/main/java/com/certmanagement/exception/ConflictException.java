// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/** The request was based on a state that changed before it could be applied; reload and retry. */
public class ConflictException extends RuntimeException {

    public ConflictException(String message) {
        super(message);
    }
}
