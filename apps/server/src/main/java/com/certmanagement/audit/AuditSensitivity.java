// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/** Whether an event records a change or a read of something sensitive (shown in a separate Access view). */
public enum AuditSensitivity {
    CHANGE,
    SENSITIVE_READ
}
