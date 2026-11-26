// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/**
 * Canonical lifecycle statuses for certificate records.
 */
public enum CertificateStatus {
    PENDING,
    ACTIVE,
    RENEW_SUCCESS,
    RENEWAL_FAILED,
    FAILED,
    EXPIRED,
    RENEWING,
    REVOKING,
    REVOKED,
    REVOCATION_FAILED,
    DELETED,

    /** Manual-issuance only: CERT_MANUAL_TXT_REQUEST sent to agent; awaiting CERT_MANUAL_TXT_RESPONSE. */
    PENDING_DNS,
    /** Manual-issuance only: TXT records returned and stored; waiting for user to add them and click Validate. */
    AWAITING_DNS,
    /** Manual-issuance only: user confirmed DNS added; CERT_MANUAL_DNS_VALIDATE sent to agent for validation. */
    VALIDATING,

    /** Manual-to-automated conversion only: manual flow was intentionally cancelled before completion. */
    CANCELLED_MANUAL
}
