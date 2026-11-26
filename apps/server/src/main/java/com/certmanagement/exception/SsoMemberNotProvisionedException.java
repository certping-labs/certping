// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * A single sign-on assertion was valid but names no member of the organization, and its configuration does not
 * provision new members. A {@link ForbiddenException}, answered as before; the audit trail records it as
 * {@code SSO_MEMBER_NOT_PROVISIONED}, so the organization's admins can tell it from an IdP refusing someone.
 */
public class SsoMemberNotProvisionedException extends ForbiddenException {

    public SsoMemberNotProvisionedException(String message) {
        super(message);
    }
}
