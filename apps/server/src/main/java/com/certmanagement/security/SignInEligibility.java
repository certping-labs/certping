// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;

/**
 * The checks every sign-in makes before issuing tokens, with password login's messages. Password
 * login keeps its own lockout check: a lockout counts failed passwords, which an SSO
 * sign-in does not use. A refusal is a {@link SignInRefusedException} (401) naming the account and the
 * reason, for the audit trail.
 */
public final class SignInEligibility {

    private static final AuditReason ACCOUNT_DISABLED = SignInFailures.ACCOUNT_DISABLED;
    private static final AuditReason ORGANIZATION_SUSPENDED = SignInFailures.ORGANIZATION_SUSPENDED;

    private SignInEligibility() {
    }

    /** {@code organization} is the one the tokens are for. */
    public static void require(User user, Organization organization) {
        if (Boolean.TRUE.equals(user.getIsDeleted())) {
            throw new SignInRefusedException(ACCOUNT_DISABLED, SignInAccount.of(user), "Account has been deleted");
        }
        if (!Boolean.TRUE.equals(user.getActive())) {
            throw new SignInRefusedException(ACCOUNT_DISABLED, SignInAccount.of(user), "Account is disabled");
        }
        if (organization != null
                && (!Boolean.TRUE.equals(organization.getActive()) || Boolean.TRUE.equals(organization.getIsDeleted()))) {
            throw new SignInRefusedException(ORGANIZATION_SUSPENDED, SignInAccount.of(user),
                    "Organization is suspended or inactive");
        }
    }
}
