// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * An organization admin's change to something only CertPing (a super admin) decides in this
 * deployment: a {@code SUPER_ADMIN_CONTROLLED} flag, or the feature flags page while it is off for
 * the organization. Maps to 403 with code {@value #CODE}.
 */
public class ManagedByCertpingException extends RuntimeException {

    public static final String CODE = "MANAGED_BY_CERTPING";

    private final String featureKey;

    public ManagedByCertpingException(String featureKey, String message) {
        super(message);
        this.featureKey = featureKey;
    }

    public String getFeatureKey() {
        return featureKey;
    }
}
