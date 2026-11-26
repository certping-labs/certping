// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;

/**
 * The account a sign-in, a sign-out or a password reset is for, as the audit trail needs it: never the
 * identifier someone typed, only the account it resolved to.
 *
 * @param organizationId the account's organization, whose trail the rows land in; {@code null} for
 *                       platform staff, who belong to none
 * @param superAdmin     a platform super admin
 */
public record SignInAccount(int userId, Long organizationId, boolean superAdmin) {

    /** {@code user}'s account; null for a user not saved yet. */
    public static SignInAccount of(User user) {
        if (user == null || user.getId() == null) {
            return null;
        }
        Organization organization = user.getOrganization();
        return new SignInAccount(user.getId(), organization == null ? null : organization.getId(),
                user.getRoleNames().contains(Permissions.ROLE_SUPER_ADMIN));
    }

    /**
     * Platform staff: a super admin, or an account with no organization. Their rows are internal, as they
     * have no customer trail to land in.
     */
    public boolean staff() {
        return superAdmin || organizationId == null;
    }
}
