// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import java.util.Map;

/**
 * {@code GET /api/v1/feature-flags/effective}: whether each feature is on for the caller's
 * organization; empty without an organization.
 *
 * @param effectiveMap feature key to effective state, every flag of the catalog
 */
public record EffectiveFeatureFlagsResponse(Map<String, Boolean> effectiveMap) {
}
