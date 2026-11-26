// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * A super admin asked for an audit retention period outside what the platform allows. Maps to 400
 * {@code AUDIT_RETENTION_OUT_OF_RANGE} with the bounds, so the settings card can say what it accepts.
 */
public class AuditRetentionOutOfRangeException extends BadRequestException {

    public static final String CODE = "AUDIT_RETENTION_OUT_OF_RANGE";

    private final int minMonths;
    private final int maxMonths;

    public AuditRetentionOutOfRangeException(Integer months, int minMonths, int maxMonths) {
        super("Audit retention must be between " + minMonths + " and " + maxMonths + " months; got " + months + ".");
        this.minMonths = minMonths;
        this.maxMonths = maxMonths;
    }

    public int getMinMonths() {
        return minMonths;
    }

    public int getMaxMonths() {
        return maxMonths;
    }
}
