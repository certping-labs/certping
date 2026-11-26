// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.service.FeatureFlagDecision.GlobalRow;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
import com.certmanagement.service.FeatureFlagDecision.OrgOverride;

/**
 * Every row {@link FeatureFlagDecision} reads for one flag and one organization, loaded once so the
 * decision can be asked again with one layer replaced: the feature lifecycle compares the answer
 * before a super admin's change (that layer rolled back) with the answer now.
 *
 * @param global         the global row, or {@code null} when it is missing (fail-open: on)
 * @param orgOverride    the organization's override, or {@code null}
 * @param orgTypeEnabled the org-type default, or {@code null} when none is set
 * @param requirement    the inputs of the flag this feature's automatic work also needs
 *                       ({@link com.certmanagement.constants.FeatureFlags#AUTOMATIC_WORK_REQUIRES}), or
 *                       {@code null} when it needs none
 */
public record FeatureFlagInputs(String featureKey, GlobalRow global, long organizationId,
                                String orgType, OrgOverride orgOverride, Boolean orgTypeEnabled,
                                FeatureFlagInputs requirement) {

    /** Whether the feature itself is on for the organization. */
    public boolean enabled() {
        return global == null || FeatureFlagDecision.decide(global, organizationId, orgType,
                orgOverride, orgTypeEnabled).effectiveEnabled();
    }

    /** Whether the feature's automatic work may run: the feature is on, and so is its requirement. */
    public boolean automaticWorkEnabled() {
        return enabled() && (requirement == null || requirement.enabled());
    }

    /** Which layer stops the feature's automatic work, or {@code null} when it may run. */
    public OffCause automaticWorkOffCause() {
        OffCause own = global == null ? null : FeatureFlagDecision.offCause(global, organizationId,
                orgType, orgOverride, orgTypeEnabled);
        if (own != null) {
            return own;
        }
        return requirement != null && !requirement.enabled() ? OffCause.REQUIREMENT : null;
    }

    /** The same inputs with the global switch at {@code enabled}. */
    public FeatureFlagInputs withGlobalEnabled(boolean enabled) {
        GlobalRow replaced = global == null ? null
                : new GlobalRow(global.featureKey(), enabled, global.scope(), global.category());
        return new FeatureFlagInputs(featureKey, replaced, organizationId, orgType, orgOverride,
                orgTypeEnabled, requirement);
    }

    /** The same inputs with the org-type default at {@code enabled} ({@code null}: none). */
    public FeatureFlagInputs withOrgTypeEnabled(Boolean enabled) {
        return new FeatureFlagInputs(featureKey, global, organizationId, orgType, orgOverride, enabled,
                requirement);
    }

    /** The same inputs with the organization's override at {@code override} ({@code null}: none). */
    public FeatureFlagInputs withOrgOverride(OrgOverride override) {
        return new FeatureFlagInputs(featureKey, global, organizationId, orgType, override,
                orgTypeEnabled, requirement);
    }

    /** The same inputs with the requirement's inputs replaced. */
    public FeatureFlagInputs withRequirement(FeatureFlagInputs replaced) {
        return new FeatureFlagInputs(featureKey, global, organizationId, orgType, orgOverride,
                orgTypeEnabled, replaced);
    }
}
