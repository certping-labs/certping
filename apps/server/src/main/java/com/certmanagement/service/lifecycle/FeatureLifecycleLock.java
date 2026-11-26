// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.service.FeatureFlagResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;

/**
 * Serializes everything that changes whether a feature is in use for one organization: the
 * organization admin's check-and-switch-off, bulk clears, the platform reconciler, and every path
 * that creates a record of a blocking kind. Each takes a transaction-scoped Postgres advisory lock on
 * a stable 64-bit key derived from (organization, feature), released at commit or rollback.
 *
 * <p>Create paths call {@link #lockAndAssertEnabled} and then re-read the flag past the cache: a
 * switch-off that committed while they waited is seen, so a record can never be created after the
 * check that found the feature clear. An advisory lock is used rather than the organization row so
 * unrelated features of one organization never wait on each other.
 */
@Component
@RequiredArgsConstructor
public class FeatureLifecycleLock {

    private static final String KEY_NAMESPACE = "certping:feature-lifecycle:";

    private final JdbcTemplate jdbc;
    private final FeatureFlagResolver resolver;

    /**
     * Waits for and takes the (organization, feature) lock for the rest of the current transaction.
     *
     * @throws org.springframework.transaction.IllegalTransactionStateException outside a transaction
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void lock(long organizationId, String featureKey) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)::text", String.class, lockKey(organizationId, featureKey));
    }

    /**
     * Takes the locks of several features in a fixed (sorted) order, so two paths needing overlapping
     * features can never wait on each other in a cycle, then confirms each is on.
     *
     * @throws FeatureDisabledException when any of them is off for the organization
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void lockAndAssertEnabled(long organizationId, Collection<String> featureKeys) {
        featureKeys.stream().distinct().sorted().forEach(featureKey -> lock(organizationId, featureKey));
        for (String featureKey : featureKeys) {
            if (!resolver.resolveUncached(featureKey, organizationId)) {
                throw new FeatureDisabledException(featureKey);
            }
        }
    }

    /** {@link #lockAndAssertEnabled(long, Collection)} for one feature. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void lockAndAssertEnabled(long organizationId, String featureKey) {
        lockAndAssertEnabled(organizationId, java.util.List.of(featureKey));
    }

    /** The key of the namespaced (feature, organization) pair; see {@link AdvisoryLockKeys#keyOf}. */
    static long lockKey(long organizationId, String featureKey) {
        return AdvisoryLockKeys.keyOf(KEY_NAMESPACE + featureKey + ":" + organizationId);
    }
}
