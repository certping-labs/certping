// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/** Who acted. {@code API_TOKEN} is reserved: the server issues no user API tokens, so no row carries it today. */
public enum AuditActorType {
    USER,
    API_TOKEN,
    /** CertPing itself: a job, a consumer or an agent result, read as "CertPing (automatic)". */
    SYSTEM,
    /** Nobody known: a request refused before it was authenticated. */
    ANONYMOUS
}
