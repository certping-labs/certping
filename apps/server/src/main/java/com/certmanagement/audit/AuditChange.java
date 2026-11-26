// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/**
 * One field's value before and after a change; {@code null} means absent. Values pass through
 * {@link AuditSanitizer}, which redacts any field whose name marks it as a secret.
 */
public record AuditChange(String field, String before, String after) {
}
