// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret;

/**
 * Where integration secrets (webhook URLs, the ServiceNow password, the PagerDuty routing key) are
 * kept. An integration row holds only the reference {@link #writeSecret} returns, never the value.
 */
public interface SecretStore {

    /**
     * Writes {@code value} and returns the reference to keep. {@code existingRef} is the reference kept
     * from an earlier write of the same secret, or null: a reference this store owns is overwritten in
     * place, anything else is replaced by a new secret named {@code name}.
     */
    String writeSecret(String existingRef, String name, String value);

    /** The value behind a reference {@link #writeSecret} returned. */
    String readSecret(String ref);
}
