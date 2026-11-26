// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.RecordImpact;

import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.LongUnaryOperator;

/**
 * A feature blocked by records the platform must not change in bulk: issuances in flight (they must
 * finish), enabled SSO connections (switching them off could lock everyone out) and credentials in
 * use. The admin follows the link and handles them one by one; {@link #clear} always refuses.
 * Instances are built in {@link FeatureLifecycleConfiguration}.
 */
public class LinkOnlyLifecycle implements FeatureLifecycle {

    private final String featureKey;
    private final BlockerKind kind;
    private final String label;
    private final String href;
    private final LongUnaryOperator countForOrganization;
    private final Function<ImpactScope, RecordImpact> impact;
    private final Function<ImpactScope, AffectedOrganizations> organizations;

    public LinkOnlyLifecycle(String featureKey, BlockerKind kind, String label, String href,
                             LongUnaryOperator countForOrganization, Function<ImpactScope, RecordImpact> impact,
                             Function<ImpactScope, AffectedOrganizations> organizations) {
        this.featureKey = featureKey;
        this.kind = kind;
        this.label = label;
        this.href = href;
        this.countForOrganization = countForOrganization;
        this.impact = impact;
        this.organizations = organizations;
    }

    @Override
    public String featureKey() {
        return featureKey;
    }

    @Override
    public List<BlockerKind> kinds() {
        return List.of(kind);
    }

    @Override
    public Set<ClearAction> supportedActions(BlockerKind blockerKind) {
        return Set.of();
    }

    @Override
    public List<Blocker> blockers(long organizationId) {
        long count = countForOrganization.applyAsLong(organizationId);
        return count == 0 ? List.of() : List.of(new Blocker(kind, label, count, href, List.of()));
    }

    @Override
    public int clear(long organizationId, BlockerKind blockerKind, ClearAction action) {
        throw new UnsupportedClearException(featureKey, blockerKind, action);
    }

    @Override
    public List<ImpactCount> impact(ImpactScope scope) {
        RecordImpact counted = impact.apply(scope);
        return List.of(new ImpactCount(kind, label, counted.records(), counted.organizations()));
    }

    @Override
    public List<AffectedOrganizations> affectedOrganizations(ImpactScope scope) {
        return List.of(organizations.apply(scope));
    }
}
