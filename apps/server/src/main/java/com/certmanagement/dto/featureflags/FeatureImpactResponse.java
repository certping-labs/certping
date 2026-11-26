// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.service.lifecycle.BlockerKind;

import java.util.List;

/**
 * {@code GET /api/v1/admin/feature-flags/{featureKey}/impact}: what switching a feature off would
 * affect, platform-wide or for one organization.
 *
 * @param organizationsAffected organizations holding affected records
 * @param notifiesAdmins        whether those organizations' admins are emailed
 * @param warnings              plain sentences for risks the counts do not show
 */
public record FeatureImpactResponse(String featureKey, long organizationsAffected, List<Item> items,
                                    boolean notifiesAdmins, List<String> warnings) {

    /** Records of one kind that would be affected. */
    public record Item(BlockerKind kind, String label, long count) {
    }
}
