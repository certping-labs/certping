// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/**
 * Who may read a row. Customer rows are the curated catalog an organization reads; internal rows are
 * the platform's own record (partition jobs, mutating requests, platform settings) and only super
 * admins see them.
 */
public enum AuditVisibility {
    CUSTOMER,
    INTERNAL
}
