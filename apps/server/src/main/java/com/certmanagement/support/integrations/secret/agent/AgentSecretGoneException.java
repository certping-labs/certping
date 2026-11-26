// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent;

/**
 * The secret behind a handle still exists in the store but its value can never be read again: a
 * destroyed or disabled GCP secret version, or an AWS secret marked for deletion. Distinct from a
 * transient failure (permissions, throttling, outages), which a retry may fix.
 *
 * <p>The message names the handle and is for logs only, never for API responses.
 */
public class AgentSecretGoneException extends RuntimeException {

    public AgentSecretGoneException(String message, Throwable cause) {
        super(message, cause);
    }
}
