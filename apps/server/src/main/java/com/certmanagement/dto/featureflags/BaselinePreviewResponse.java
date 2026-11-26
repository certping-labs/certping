// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import java.util.List;

/**
 * {@code GET /api/v1/admin/feature-lifecycle/baseline-preview}: what the baseline would pause if the
 * {@code FEATURE_LIFECYCLE_RECONCILE} switch were turned on now, per platform-pausable feature.
 *
 * @param features one entry per feature whose records the platform pauses, by feature key
 */
public record BaselinePreviewResponse(List<FeaturePreview> features) {

    /**
     * @param organizations organizations whose records would be paused
     * @param records       records that would be paused
     * @param byCause       the same, split by the layer that has the feature off
     */
    public record FeaturePreview(String featureKey, long organizations, long records, List<CausePreview> byCause) {
    }

    /**
     * @param cause GLOBAL, ORG_OVERRIDE or ORG_TYPE
     * @param items per kind, the records that would be paused
     */
    public record CausePreview(String cause, long organizations, long records, List<ItemCount> items) {
    }

    /** Records of one kind. */
    public record ItemCount(String kind, String label, long count) {
    }
}
