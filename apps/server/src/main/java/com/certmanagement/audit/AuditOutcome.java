// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

public enum AuditOutcome {
    SUCCESS,
    FAILURE,
    /** Started and handed to something that reports back later, such as an agent. */
    PENDING
}
