// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagDecision.OrgOverride;
import com.certmanagement.service.FeatureFlagInputs;

/**
 * One super admin flag change still to be applied by the feature lifecycle (row of
 * {@code feature_lifecycle_transition}): which layer changed, for whom, and its value before the
 * change, so the reconciler can tell per organization whether this change switched the feature off
 * (a forced pause, emailed) or it was off already (baseline, silent).
 *
 * @param beforeEnabled     the layer before the change: the global switch; the org-type default
 *                          ({@code null}: none); the org override's enabled ({@code null}: none)
 * @param beforeAdminLocked whether the org override before the change was a super admin's
 * @param cursorPhase       for GLOBAL and ORG_TYPE rows, the pass the organization walk is in
 * @param cursorOrganizationId the last organization the walk finished in that pass
 */
public record ForcedTransition(long id, String featureKey, Scope scope, String orgType, Long organizationId,
                               Boolean beforeEnabled, Boolean beforeAdminLocked, Integer actorUserId,
                               SweepCursor.Pass cursorPhase, long cursorOrganizationId) {

    /** The flag layer a super admin changed. */
    public enum Scope { GLOBAL, ORG_TYPE, ORGANIZATION }

    /** Whether this change can affect the organization (of {@code orgType}). */
    boolean covers(long candidateOrganizationId, String candidateOrgType) {
        return switch (scope) {
            case GLOBAL -> true;
            case ORG_TYPE -> orgType.equals(candidateOrgType);
            case ORGANIZATION -> organizationId == candidateOrganizationId;
        };
    }

    /**
     * {@code inputs} with the layer this change wrote put back to its value before the change: a layer of
     * the inputs' own flag, or of the flag their automatic work requires.
     */
    FeatureFlagInputs rollBack(FeatureFlagInputs inputs) {
        FeatureFlagInputs requirement = inputs.requirement();
        if (requirement != null && featureKey.equals(requirement.featureKey())) {
            return inputs.withRequirement(rollBackLayer(requirement));
        }
        return rollBackLayer(inputs);
    }

    private FeatureFlagInputs rollBackLayer(FeatureFlagInputs inputs) {
        return switch (scope) {
            case GLOBAL -> inputs.withGlobalEnabled(Boolean.TRUE.equals(beforeEnabled));
            case ORG_TYPE -> inputs.withOrgTypeEnabled(beforeEnabled);
            case ORGANIZATION -> inputs.withOrgOverride(beforeEnabled == null ? null
                    : new OrgOverride(beforeEnabled, Boolean.TRUE.equals(beforeAdminLocked)));
        };
    }
}
