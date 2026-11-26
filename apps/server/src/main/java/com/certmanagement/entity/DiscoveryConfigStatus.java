// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

public enum DiscoveryConfigStatus {
    READY,
    STARTED,
    IN_PROGRESS,
    COMPLETE,
    /** The last run finished but could not read some scopes; see its scan's failed scopes. */
    PARTIAL,
    FAILED,
    CONFIG_REQUIRED,
    CREDENTIAL_INVALID,
    /** The last run was stopped because {@code DISCOVERY} was switched off for the organization. */
    CANCELLED
}
