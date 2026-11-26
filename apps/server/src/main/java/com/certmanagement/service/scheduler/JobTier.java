// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

/**
 * What a background job owes the customer when its feature is switched off. Declared per job in
 * {@link JobPolicy}; {@link SchedulerExecutionPolicy} enforces it.
 */
public enum JobTier {

    /**
     * Work that only exists because a feature is on (discovery rescans, IoT sync). Stops when any
     * of its feature flags is off platform-wide, and skips rows of an organization that has it off.
     */
    FEATURE_WORK,

    /**
     * Protects things the customer already has (renewing issued certificates, expiry alerts and
     * marking, revoking IoT certificates). Keeps running regardless of product flags; only its ops
     * kill switch stops it.
     */
    CUSTOMER_PROTECTION,

    /**
     * The platform's own obligations (token rotation, usage reporting, purges, queue hygiene). Never
     * tied to a product flag; only its ops kill switch stops it.
     */
    PLATFORM_OBLIGATION
}
