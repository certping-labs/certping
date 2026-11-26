// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.enums;

public enum NotificationAction {
    //Account

    //Password
    PASSWORD_CHANGE_SUCCESS,
    RESET_PASSWORD,

    //SSL ISSUANCE (Automated Management - new certificate)
    CERT_ISSUANCE_SUCCESS,
    CERT_ISSUANCE_FAILED,
    CERT_MANUAL_TXT_READY,

    //SSL RENEWAL (Automated Management)
    CERT_RENEWAL_SUCCESS,
    CERT_RENEWAL_FAILED,
    // Published by the server's CertResponseProcessor right after CERT_RENEWAL_SUCCESS when automatic
    // deployment is turned off for the organization, so the renewed certificate is not installed anywhere.
    // Deliver-once under its requestId ("<renewal request>:not-deployed"); see DeliverOncePolicy.
    CERT_RENEWED_NOT_DEPLOYED,

    //CERT LIFECYCLE — revocation & expiry (published by the server)
    CERT_REVOKED,
    // the agent answered a revocation command with an error, so the certificate is still valid
    CERT_REVOCATION_FAILED,
    CERT_EXPIRED,
    CERT_EXPIRY_ALERT,
    // A CertPing DNS key expires, after which certificates validated through it stop renewing: 30 days and 7 days
    // before. Deliver-once under templateFields.idempotencyKey; see DeliverOncePolicy.
    CERTPING_DNS_KEY_EXPIRING,

    //IOT / MACHINE IDENTITY — device certificates are issued and renewed continuously by SCEP, so
    //this is a scheduled per-organization activity rollup rather than a per-certificate event.
    IOT_ACTIVITY_DIGEST,
    //Operational failures that must not wait for the next digest. Two actions rather than one per
    //scenario: the scenario travels in the payload, and the split is what routes CRITICAL to the
    //incident providers.
    IOT_CRITICAL_ALERT,
    IOT_WARNING_ALERT,

    //SCHEDULER (Certificate Automation)
    SCHEDULER_CREDENTIAL_PARSE_FAILED,
    SCHEDULER_RENEWAL_SEND_FAILED,

    //DEPLOYMENT (Certificate Distribution)
    CERT_DEPLOYMENT_SUCCESS,
    CERT_DEPLOYMENT_FAILED,

    // FEATURE LIFECYCLE — the server tells an organization's admins that CertPing turned a feature off
    // (its records are platform-paused) or back on (they resume). Deliver-once under the publisher's
    // templateFields.idempotencyKey; see DeliverOncePolicy.
    FEATURE_PAUSED,
    FEATURE_RESUMED,

    // SYSTEM / PLATFORM OPERATIONAL ALERTS — recipient is the super admin (direct email), published
    // by the server's OperationalAlertPublisher (queue depth / DLQ health). Templates resolve as
    // name().toLowerCase().replace("_","-").
    SYSTEM_DLQ_ALERT,
    SYSTEM_QUEUE_DEPTH_WARNING,
    SYSTEM_QUEUE_ALERT_RESOLVED
}
