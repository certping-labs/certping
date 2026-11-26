// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/**
 * Canonical event types written to the {@code certificate_events} audit table.
 *
 * <p>Stored as {@link #name()} (plain VARCHAR) — no Flyway migration required when values are added.
 * Follow the same pattern as {@link CertificateStatus}: call {@code CertEventType.X.name()} wherever
 * a {@code String eventType} is expected.
 */
public enum CertEventType {

    // ── Issuance ─────────────────────────────────────────────────────────────
    ISSUANCE_REQUESTED,
    ISSUANCE_PUBLISH_FAILED,
    ISSUANCE_SUCCESS,
    ISSUANCE_FAILED,

    // ── Renewal ──────────────────────────────────────────────────────────────
    RENEWAL_REQUESTED,
    RENEWAL_PUBLISH_FAILED,
    RENEWAL_SUCCESS,
    RENEWAL_FAILED,
    /**
     * Automatic renewal was left off after an issuance or renewal succeeded: {@code CERTIFICATE_RENEWAL}
     * or the certificate's CA flag is off for the org.
     */
    AUTO_RENEW_SKIPPED_FEATURE_OFF,

    // ── Deployment ───────────────────────────────────────────────────────────
    DEPLOYMENT_REQUESTED,
    DEPLOYMENT_PUBLISH_FAILED,
    DEPLOYMENT_SUCCESS,
    DEPLOYMENT_FAILED,
    /** Auto-deploy after issuance/renewal did not run: {@code CERTIFICATE_DEPLOYMENT} is off for the org. */
    AUTO_DEPLOY_SKIPPED_FEATURE_OFF,

    // ── Revocation ───────────────────────────────────────────────────────────
    REVOCATION_REQUESTED,
    REVOCATION_FAILED,
    REVOCATION_SUCCESS,

    // ── Manual issuance ──────────────────────────────────────────────────────
    MANUAL_TXT_REQUESTED,
    MANUAL_TXT_PUBLISH_FAILED,
    MANUAL_DNS_VALIDATE_REQUESTED,
    MANUAL_DNS_VALIDATE_PUBLISH_FAILED,
    MANUAL_TXT_RECEIVED,

    // ── Conversion (manual -> automated) ────────────────────────────────────
    CONVERSION_REQUESTED,
    CONVERSION_DEFERRED,
    CONVERSION_CANCELLED_MANUAL,
    CONVERSION_TRIGGERED_RENEWAL,
    CONVERSION_TRIGGERED_ISSUANCE,

    // ── Export ───────────────────────────────────────────────────────────────
    EXPORTED,

    // ── Lifecycle ────────────────────────────────────────────────────────────
    CERT_DELETED,
    CERT_EXPIRED,
    STATUS_CHANGED
}
