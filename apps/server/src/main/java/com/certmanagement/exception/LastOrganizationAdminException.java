// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/** A change would leave an organization without an active organization admin. */
public class LastOrganizationAdminException extends RuntimeException {

    public LastOrganizationAdminException() {
        super("An organization needs at least one active admin");
    }
}
