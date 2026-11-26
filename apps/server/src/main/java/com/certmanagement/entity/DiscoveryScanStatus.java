// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

public enum DiscoveryScanStatus {
    DISPATCHED,
    RECEIVING,
    COMPLETE,
    /**
     * Finished, but the agent could not read some scopes (an AWS account or region, a vault, a
     * namespace). Their certificates were left as they were, never marked MISSING.
     */
    PARTIAL,
    FAILED,
    /** Ended without results because {@code DISCOVERY} was switched off for the organization. */
    CANCELLED
}
