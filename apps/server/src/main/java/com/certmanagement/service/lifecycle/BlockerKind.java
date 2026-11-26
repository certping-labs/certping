// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

/**
 * A kind of record that keeps a feature in use for an organization, so the organization admin cannot
 * switch the feature off until it is cleared.
 */
public enum BlockerKind {
    DEPLOYMENT_TARGETS,
    AUTO_RENEW_CERTS,
    PENDING_ISSUANCES,
    AUTO_RENEW_CERTS_ON_CA,
    CREDENTIALS_IN_USE,
    RUNNING_DISCOVERY_SCANS,
    ACTIVE_INTEGRATIONS
}
