// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.util.Set;

/**
 * The fields of a credential a row names but never holds a value of ({@link AuditEventType.Allowed#nameOnly}):
 * the credential details a customer pastes ({@code credJson}: keys, tokens, client secrets, passwords, service
 * account JSON), where they are kept ({@code secretHandle}: a secret store location, which names the vault), and
 * the deployment scope ({@code configJson}, which names the customer's cloud accounts and resources). A row says
 * that one of them was supplied or changed, never what it holds.
 */
public final class CredentialFields {

    public static final String DETAILS = "credJson";
    public static final String SECRET_HANDLE = "secretHandle";
    public static final String CONFIGURATION = "configJson";

    /** {@link #DETAILS}, {@link #SECRET_HANDLE}, {@link #CONFIGURATION}, and a client secret by its own name. */
    public static final Set<String> KEPT_BY_NAME = Set.of(DETAILS, SECRET_HANDLE, CONFIGURATION, "clientSecret");

    private CredentialFields() {
    }
}
