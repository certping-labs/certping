// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * A certificate name has no DNS credential in its domain's credential configuration, so the certificate cannot be
 * renewed as it is. The scheduled renewal parks the schedule rather than retrying it.
 */
public class MissingDnsCredentialConfigurationException extends ResourceNotFoundException {

    public MissingDnsCredentialConfigurationException(String message) {
        super(message);
    }
}
