// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.exception.UnauthorizedException;

/**
 * A sign-in refused for a reason the platform knows: answered as any {@link UnauthorizedException} (401,
 * with the same message the caller always got), and carrying what the audit trail and the
 * {@code AUTH_EVENT} log line need without ever reading the message: the reason code and, when the
 * attempt resolved to one, the account.
 */
public class SignInRefusedException extends UnauthorizedException {

    private final transient AuditReason reason;
    private final transient SignInAccount account;

    /**
     * @param account the account the attempt resolved to; {@code null} when it resolved to none (an unknown
     *                identifier, an identity provider that named no one)
     */
    public SignInRefusedException(AuditReason reason, SignInAccount account, String message) {
        super(message);
        this.reason = reason == null ? AuditReason.INTERNAL_ERROR : reason;
        this.account = account;
    }

    public AuditReason reason() {
        return reason;
    }

    /** The account the refused attempt was for, or null. */
    public SignInAccount account() {
        return account;
    }
}
