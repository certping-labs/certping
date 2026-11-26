// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.ImpactScope;
import java.util.List;
import java.util.Set;

/**
 * What switching one feature off means for an organization's records: what keeps it in use
 * ({@link #blockers}), how an organization admin clears that in bulk ({@link #clear}), and what a
 * platform administrator's switch-off would touch across organizations ({@link #impact}).
 *
 * <p>One implementation per feature with records to clear, registered in
 * {@link FeatureLifecycleRegistry}; a feature without one has no blockers. Every method runs a fixed
 * number of aggregate or set-based statements, never one per record.
 */
public interface FeatureLifecycle {

    /** The {@code FeatureFlags} key this lifecycle belongs to. */
    String featureKey();

    /** Every kind this feature reports, whether or not the organization has any. */
    List<BlockerKind> kinds();

    /** The bulk actions that clear {@code kind}; empty for a link-only kind. */
    Set<ClearAction> supportedActions(BlockerKind kind);

    /** The kinds the organization still has records of (count above zero), with their counts. */
    List<Blocker> blockers(long organizationId);

    /**
     * Applies {@code action} to every record of {@code kind} in the organization, in the caller's
     * transaction, with the same ledger and cleanup semantics as the single-record path.
     *
     * @return records changed
     * @throws UnsupportedClearException when {@code action} does not clear {@code kind}
     */
    int clear(long organizationId, BlockerKind kind, ClearAction action);

    /** Counts per kind across the organizations in {@code scope}. */
    List<ImpactCount> impact(ImpactScope scope);

    /**
     * The organizations holding records of each kind in {@code scope}, for one distinct count across
     * kinds (an organization with records of two kinds is affected once).
     */
    List<AffectedOrganizations> affectedOrganizations(ImpactScope scope);
}
