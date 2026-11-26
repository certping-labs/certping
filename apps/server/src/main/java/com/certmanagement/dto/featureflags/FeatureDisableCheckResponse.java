// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.service.lifecycle.Blocker;

import java.util.List;

/**
 * {@code GET /api/v1/feature-flags/{featureKey}/disable-check}: whether the organization admin can
 * switch the feature off now, and if not, what to clear first.
 */
public record FeatureDisableCheckResponse(String featureKey, boolean canDisable, List<Blocker> blockers) {

    public static FeatureDisableCheckResponse of(String featureKey, List<Blocker> blockers) {
        return new FeatureDisableCheckResponse(featureKey, blockers.isEmpty(), List.copyOf(blockers));
    }
}
