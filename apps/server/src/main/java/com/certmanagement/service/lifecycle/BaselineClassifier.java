// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decides which organizations of a page the BASELINE would pause, and why: the feature's automatic work
 * is off for them (the feature or the flag that work requires, {@link FeatureFlags#AUTOMATIC_WORK_REQUIRES},
 * decided by {@link com.certmanagement.service.FeatureFlagDecision} over one batch load of the page) and no
 * pending forced change covers them (those are the forced walk's to apply, with their email). The
 * baseline sweep and the baseline preview both use it, so the preview shows exactly what the sweep
 * then pauses.
 */
@Component
@RequiredArgsConstructor
class BaselineClassifier {

    private final FeatureFlagResolver resolver;
    private final ForcedTransitionStore transitions;

    /**
     * The organizations of {@code organizationIds} the baseline would pause, each with the layer that
     * has the feature off, in page order. Five queries for the page, whatever its size.
     */
    Map<Long, OffCause> baselineCandidates(String featureKey, List<Long> organizationIds) {
        Map<Long, FeatureFlagInputs> inputs = resolver.loadInputs(featureKey, organizationIds);
        List<ForcedTransition> pending = transitions.pendingFor(FeatureFlags.automaticWorkKeys(featureKey),
                organizationIds);
        Map<Long, OffCause> candidates = new LinkedHashMap<>();
        for (Long organizationId : organizationIds) {
            FeatureFlagInputs organization = inputs.get(organizationId);
            if (organization == null || organization.automaticWorkEnabled()) {
                continue;
            }
            boolean forcedChangePending = pending.stream()
                    .anyMatch(transition -> transition.covers(organizationId, organization.orgType()));
            if (!forcedChangePending) {
                candidates.put(organizationId, organization.automaticWorkOffCause());
            }
        }
        return candidates;
    }
}
